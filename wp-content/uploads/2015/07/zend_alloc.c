/*
   +----------------------------------------------------------------------+
   | Zend Engine                                                          |
   +----------------------------------------------------------------------+
   | Copyright (c) 1998-2015 Zend Technologies Ltd. (http://www.zend.com) |
   +----------------------------------------------------------------------+
   | This source file is subject to version 2.00 of the Zend license,     |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.zend.com/license/2_00.txt.                                |
   | If you did not receive a copy of the Zend license and are unable to  |
   | obtain it through the world-wide-web, please send a note to          |
   | license@zend.com so we can mail you a copy immediately.              |
   +----------------------------------------------------------------------+
   | Authors: Andi Gutmans <andi@zend.com>                                |
   |          Zeev Suraski <zeev@zend.com>                                |
   |          Dmitry Stogov <dmitry@zend.com>                             |
   +----------------------------------------------------------------------+
*/

/* $Id$ */

#include "zend.h"
#include "zend_alloc.h"
#include "zend_globals.h"
#include "zend_operators.h"

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef ZEND_WIN32
# include <wincrypt.h>
# include <process.h>
#endif

#ifndef ZEND_MM_HEAP_PROTECTION
# define ZEND_MM_HEAP_PROTECTION ZEND_DEBUG
#endif

#ifndef ZEND_MM_SAFE_UNLINKING
# define ZEND_MM_SAFE_UNLINKING 1
#endif

#ifndef ZEND_MM_COOKIES
# define ZEND_MM_COOKIES ZEND_DEBUG
#endif

#ifdef _WIN64
# define PTR_FMT "0x%0.16I64x"
/*
#elif sizeof(long) == 8
# define PTR_FMT "0x%0.16lx"
*/
#else
# define PTR_FMT "0x%0.8lx"
#endif

#if ZEND_DEBUG
void zend_debug_alloc_output(char *format, ...)
{
	char output_buf[256];
	va_list args;

	va_start(args, format);
	vsprintf(output_buf, format, args);
	va_end(args);

#ifdef ZEND_WIN32
	OutputDebugString(output_buf);
#else
	fprintf(stderr, "%s", output_buf);
#endif
}
#endif

#if (defined (__GNUC__) && __GNUC__ > 2 ) && !defined(__INTEL_COMPILER) && !defined(DARWIN) && !defined(__hpux) && !defined(_AIX)
static void zend_mm_panic(const char *message) __attribute__ ((noreturn));
#endif

static void zend_mm_panic(const char *message)
{
	fprintf(stderr, "%s\n", message);
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
	fflush(stderr);
#endif
#if ZEND_DEBUG && defined(HAVE_KILL) && defined(HAVE_GETPID)
	kill(getpid(), SIGSEGV);
#endif
	exit(1);
}

/*******************/
/* Storage Manager */
/*******************/

#ifdef ZEND_WIN32
#  define HAVE_MEM_WIN32    /* use VirtualAlloc() to allocate memory     */
#endif
#define HAVE_MEM_MALLOC     /* use malloc() to allocate segments         */

#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_LIMITS_H
#include <limits.h>
#endif
#include <fcntl.h>
#include <errno.h>

#if defined(HAVE_MEM_MMAP_ANON) || defined(HAVE_MEM_MMAP_ZERO)
# ifdef HAVE_MREMAP
#  ifndef _GNU_SOURCE
#   define _GNU_SOURCE
#  endif
#  ifndef __USE_GNU
#   define __USE_GNU
#  endif
# endif
# include <sys/mman.h>
# ifndef MAP_ANON
#  ifdef MAP_ANONYMOUS
#   define MAP_ANON MAP_ANONYMOUS
#  endif
# endif
# ifndef MREMAP_MAYMOVE
#  define MREMAP_MAYMOVE 0
# endif
# ifndef MAP_FAILED
#  define MAP_FAILED ((void*)-1)
# endif
#endif

static zend_mm_storage* zend_mm_mem_dummy_init(void *params)
{
	return malloc(sizeof(zend_mm_storage));
}

static void zend_mm_mem_dummy_dtor(zend_mm_storage *storage)
{
	free(storage);
}

static void zend_mm_mem_dummy_compact(zend_mm_storage *storage)
{
}

#if defined(HAVE_MEM_MMAP_ANON) || defined(HAVE_MEM_MMAP_ZERO)

static zend_mm_segment* zend_mm_mem_mmap_realloc(zend_mm_storage *storage, zend_mm_segment* segment, size_t size)
{
	zend_mm_segment *ret;
#ifdef HAVE_MREMAP
#if defined(__NetBSD__)
	/* NetBSD 5 supports mremap but takes an extra newp argument */
	ret = (zend_mm_segment*)mremap(segment, segment->size, segment, size, MREMAP_MAYMOVE);
#else
	ret = (zend_mm_segment*)mremap(segment, segment->size, size, MREMAP_MAYMOVE);
#endif
	if (ret == MAP_FAILED) {
#endif
		ret = storage->handlers->_alloc(storage, size);
		if (ret) {
			memcpy(ret, segment, size > segment->size ? segment->size : size);
			storage->handlers->_free(storage, segment);
		}
#ifdef HAVE_MREMAP
	}
#endif
	return ret;
}

static void zend_mm_mem_mmap_free(zend_mm_storage *storage, zend_mm_segment* segment)
{
	munmap((void*)segment, segment->size);
}

#endif

#ifdef HAVE_MEM_MMAP_ANON

static zend_mm_segment* zend_mm_mem_mmap_anon_alloc(zend_mm_storage *storage, size_t size)
{
	zend_mm_segment *ret = (zend_mm_segment*)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (ret == MAP_FAILED) {
		ret = NULL;
	}
	return ret;
}

# define ZEND_MM_MEM_MMAP_ANON_DSC {"mmap_anon", zend_mm_mem_dummy_init, zend_mm_mem_dummy_dtor, zend_mm_mem_dummy_compact, zend_mm_mem_mmap_anon_alloc, zend_mm_mem_mmap_realloc, zend_mm_mem_mmap_free}

#endif

#ifdef HAVE_MEM_MMAP_ZERO

static int zend_mm_dev_zero_fd = -1;

static zend_mm_storage* zend_mm_mem_mmap_zero_init(void *params)
{
	if (zend_mm_dev_zero_fd == -1) {
		zend_mm_dev_zero_fd = open("/dev/zero", O_RDWR, S_IRUSR | S_IWUSR);
	}
	if (zend_mm_dev_zero_fd >= 0) {
		return malloc(sizeof(zend_mm_storage));
	} else {
		return NULL;
	}
}

static void zend_mm_mem_mmap_zero_dtor(zend_mm_storage *storage)
{
	close(zend_mm_dev_zero_fd);
	free(storage);
}

static zend_mm_segment* zend_mm_mem_mmap_zero_alloc(zend_mm_storage *storage, size_t size)
{
	zend_mm_segment *ret = (zend_mm_segment*)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, zend_mm_dev_zero_fd, 0);
	if (ret == MAP_FAILED) {
		ret = NULL;
	}
	return ret;
}

# define ZEND_MM_MEM_MMAP_ZERO_DSC {"mmap_zero", zend_mm_mem_mmap_zero_init, zend_mm_mem_mmap_zero_dtor, zend_mm_mem_dummy_compact, zend_mm_mem_mmap_zero_alloc, zend_mm_mem_mmap_realloc, zend_mm_mem_mmap_free}

#endif

#ifdef HAVE_MEM_WIN32

static zend_mm_storage* zend_mm_mem_win32_init(void *params)
{
	HANDLE heap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0);
	zend_mm_storage* storage;

	if (heap == NULL) {
		return NULL;
	}
	storage = (zend_mm_storage*)malloc(sizeof(zend_mm_storage));
	if (storage == NULL) {
		HeapDestroy(heap);
		return NULL;
	}
	storage->data = (void*) heap;
	return storage;
}

static void zend_mm_mem_win32_dtor(zend_mm_storage *storage)
{
	HeapDestroy((HANDLE)storage->data);
	free(storage);
}

static void zend_mm_mem_win32_compact(zend_mm_storage *storage)
{
    HeapDestroy((HANDLE)storage->data);
    storage->data = (void*)HeapCreate(HEAP_NO_SERIALIZE, 0, 0);
}

static zend_mm_segment* zend_mm_mem_win32_alloc(zend_mm_storage *storage, size_t size)
{
	return (zend_mm_segment*) HeapAlloc((HANDLE)storage->data, HEAP_NO_SERIALIZE, size);
}

static void zend_mm_mem_win32_free(zend_mm_storage *storage, zend_mm_segment* segment)
{
	HeapFree((HANDLE)storage->data, HEAP_NO_SERIALIZE, segment);
}

static zend_mm_segment* zend_mm_mem_win32_realloc(zend_mm_storage *storage, zend_mm_segment* segment, size_t size)
{
	return (zend_mm_segment*) HeapReAlloc((HANDLE)storage->data, HEAP_NO_SERIALIZE, segment, size);
}

# define ZEND_MM_MEM_WIN32_DSC {"win32", zend_mm_mem_win32_init, zend_mm_mem_win32_dtor, zend_mm_mem_win32_compact, zend_mm_mem_win32_alloc, zend_mm_mem_win32_realloc, zend_mm_mem_win32_free}

#endif

#ifdef HAVE_MEM_MALLOC

static zend_mm_segment* zend_mm_mem_malloc_alloc(zend_mm_storage *storage, size_t size)
{
	return (zend_mm_segment*)malloc(size);
}

static zend_mm_segment* zend_mm_mem_malloc_realloc(zend_mm_storage *storage, zend_mm_segment *ptr, size_t size)
{
	return (zend_mm_segment*)realloc(ptr, size);
}

static void zend_mm_mem_malloc_free(zend_mm_storage *storage, zend_mm_segment *ptr)
{
	free(ptr);
}

# define ZEND_MM_MEM_MALLOC_DSC {"malloc", zend_mm_mem_dummy_init, zend_mm_mem_dummy_dtor, zend_mm_mem_dummy_compact, zend_mm_mem_malloc_alloc, zend_mm_mem_malloc_realloc, zend_mm_mem_malloc_free}

#endif

static const zend_mm_mem_handlers mem_handlers[] = {
#ifdef HAVE_MEM_WIN32
	ZEND_MM_MEM_WIN32_DSC,  //win32环境分配内存函数
#endif
#ifdef HAVE_MEM_MALLOC
	ZEND_MM_MEM_MALLOC_DSC, //linux环境分配内存函数
#endif
#ifdef HAVE_MEM_MMAP_ANON
	ZEND_MM_MEM_MMAP_ANON_DSC,
#endif
#ifdef HAVE_MEM_MMAP_ZERO
	ZEND_MM_MEM_MMAP_ZERO_DSC,
#endif
	{NULL, NULL, NULL, NULL, NULL, NULL}
};

# define ZEND_MM_STORAGE_DTOR()						heap->storage->handlers->dtor(heap->storage)
# define ZEND_MM_STORAGE_ALLOC(size)				heap->storage->handlers->_alloc(heap->storage, size)
# define ZEND_MM_STORAGE_REALLOC(ptr, size)			heap->storage->handlers->_realloc(heap->storage, ptr, size)
# define ZEND_MM_STORAGE_FREE(ptr)					heap->storage->handlers->_free(heap->storage, ptr)

/****************/
/* Heap Manager */
/****************/

#define MEM_BLOCK_VALID  0x7312F8DC
#define	MEM_BLOCK_FREED  0x99954317
#define	MEM_BLOCK_CACHED 0xFB8277DC
#define	MEM_BLOCK_GUARD  0x2A8FCC84
#define	MEM_BLOCK_LEAK   0x6C5E8F2D

/* mm block type */
typedef struct _zend_mm_block_info {
#if ZEND_MM_COOKIES
	size_t _cookie;
#endif
	size_t _size;  //本块大小和标记
	size_t _prev;  //物理上一块大小和标记
} zend_mm_block_info;

#if ZEND_DEBUG

typedef struct _zend_mm_debug_info {
	const char *filename;
	uint lineno;
	const char *orig_filename;
	uint orig_lineno;
	size_t size;
#if ZEND_MM_HEAP_PROTECTION
	unsigned int start_magic;
#endif
} zend_mm_debug_info;

#elif ZEND_MM_HEAP_PROTECTION

typedef struct _zend_mm_debug_info {
	size_t size;
	unsigned int start_magic;
} zend_mm_debug_info;

#endif

typedef struct _zend_mm_block {
	zend_mm_block_info info;
#if ZEND_DEBUG
	unsigned int magic;
# ifdef ZTS
	THREAD_T thread_id;
# endif
	zend_mm_debug_info debug;
#elif ZEND_MM_HEAP_PROTECTION
	zend_mm_debug_info debug;
#endif
} zend_mm_block;

typedef struct _zend_mm_small_free_block {
	zend_mm_block_info info;  //block头部
#if ZEND_DEBUG
	unsigned int magic;
# ifdef ZTS
	THREAD_T thread_id;
# endif
#endif
	struct _zend_mm_free_block *prev_free_block;  //逻辑上一块空闲块
	struct _zend_mm_free_block *next_free_block;  //逻辑下一块空闲块
} zend_mm_small_free_block;

typedef struct _zend_mm_free_block {
	zend_mm_block_info info;  //block头部
#if ZEND_DEBUG
	unsigned int magic;
# ifdef ZTS
	THREAD_T thread_id;
# endif
#endif
	struct _zend_mm_free_block *prev_free_block;  //逻辑上一块空闲块
	struct _zend_mm_free_block *next_free_block;  //逻辑下一块空闲块

	struct _zend_mm_free_block **parent;  //指向双亲最孩子或右孩子，方便对其操作
	struct _zend_mm_free_block *child[2]; //左右孩子
} zend_mm_free_block;

#define ZEND_MM_NUM_BUCKETS (sizeof(size_t) << 3)

#define ZEND_MM_CACHE 1
#define ZEND_MM_CACHE_SIZE (ZEND_MM_NUM_BUCKETS * 4 * 1024)

#ifndef ZEND_MM_CACHE_STAT
# define ZEND_MM_CACHE_STAT 0
#endif

struct _zend_mm_heap {
	int                 use_zend_alloc;  //是否使用ZMM
	void               *(*_malloc)(size_t); //不使用ZMM时调用的分配函数
	void                (*_free)(void*);  //不使用ZMM时调用的释放函数
	void               *(*_realloc)(void*, size_t); //不使用ZMM时调用的重分配函数
	size_t              free_bitmap;  //小块内存位图
	size_t              large_free_bitmap;  //大块内存位图
	size_t              block_size; //段最小大小
	size_t              compact_size; 
	zend_mm_segment    *segments_list; //段链表
	zend_mm_storage    *storage;  //存储层，保存了不同平台的分配实现
	size_t              real_size;  //ZMM大小
	size_t              real_peak;  //ZMM大小峰值
	size_t              limit;  //ZMM大小限制
	size_t              size;   //ZMM分配出去的内存大小
	size_t              peak;   //ZMM分配出去的内存大小峰值
	size_t              reserve_size;  //预留的内存大小
	void               *reserve;  //预留的内存
	int                 overflow;
	int                 internal;
#if ZEND_MM_CACHE
	unsigned int        cached;  //缓存内存块的大小
	zend_mm_free_block *cache[ZEND_MM_NUM_BUCKETS]; //缓存内存块
#endif
	zend_mm_free_block *free_buckets[ZEND_MM_NUM_BUCKETS*2];  //小块内存数组
	zend_mm_free_block *large_free_buckets[ZEND_MM_NUM_BUCKETS];  //大块内存数组
	zend_mm_free_block *rest_buckets[2];  //保留内存
	int                 rest_count;  //保留内存大小
#if ZEND_MM_CACHE_STAT  //缓存状态信息
	struct {
		int count;
		int max_count;
		int hit;
		int miss;
	} cache_stat[ZEND_MM_NUM_BUCKETS+1];
#endif
};

#define ZEND_MM_SMALL_FREE_BUCKET(heap, index) \
	(zend_mm_free_block*) ((char*)&heap->free_buckets[index * 2] + \
		sizeof(zend_mm_free_block*) * 2 - \
		sizeof(zend_mm_small_free_block))

#define ZEND_MM_REST_BUCKET(heap) \
	(zend_mm_free_block*)((char*)&heap->rest_buckets[0] + \
		sizeof(zend_mm_free_block*) * 2 - \
		sizeof(zend_mm_small_free_block))

#define ZEND_MM_REST_BLOCK ((zend_mm_free_block**)(zend_uintptr_t)(1))

#define ZEND_MM_MAX_REST_BLOCKS 16

#if ZEND_MM_COOKIES

static unsigned int _zend_mm_cookie = 0;

# define ZEND_MM_COOKIE(block) \
	(((size_t)(block)) ^ _zend_mm_cookie)
# define ZEND_MM_SET_COOKIE(block) \
	(block)->info._cookie = ZEND_MM_COOKIE(block)
# define ZEND_MM_CHECK_COOKIE(block) \
	if (UNEXPECTED((block)->info._cookie != ZEND_MM_COOKIE(block))) { \
		zend_mm_panic("zend_mm_heap corrupted"); \
	}
#else
# define ZEND_MM_SET_COOKIE(block)
# define ZEND_MM_CHECK_COOKIE(block)
#endif

/* Default memory segment size */
#define ZEND_MM_SEG_SIZE   (256 * 1024)

/* Reserved space for error reporting in case of memory overflow */
#define ZEND_MM_RESERVE_SIZE            (8*1024)

#ifdef _WIN64
# define ZEND_MM_LONG_CONST(x)	(x##i64)
#else
# define ZEND_MM_LONG_CONST(x)	(x##L)
#endif

#define ZEND_MM_TYPE_MASK		ZEND_MM_LONG_CONST(0x3)

#define ZEND_MM_FREE_BLOCK		ZEND_MM_LONG_CONST(0x0)
#define ZEND_MM_USED_BLOCK		ZEND_MM_LONG_CONST(0x1)
#define ZEND_MM_GUARD_BLOCK		ZEND_MM_LONG_CONST(0x3)

#define ZEND_MM_BLOCK(b, type, size)	do { \
											size_t _size = (size); \
											(b)->info._size = (type) | _size; \
											ZEND_MM_BLOCK_AT(b, _size)->info._prev = (type) | _size; \
											ZEND_MM_SET_COOKIE(b); \
										} while (0);
#define ZEND_MM_LAST_BLOCK(b)			do { \
		(b)->info._size = ZEND_MM_GUARD_BLOCK | ZEND_MM_ALIGNED_HEADER_SIZE; \
		ZEND_MM_SET_MAGIC(b, MEM_BLOCK_GUARD); \
 	} while (0);
#define ZEND_MM_BLOCK_SIZE(b)			((b)->info._size & ~ZEND_MM_TYPE_MASK)
#define ZEND_MM_IS_FREE_BLOCK(b)		(!((b)->info._size & ZEND_MM_USED_BLOCK))
#define ZEND_MM_IS_USED_BLOCK(b)		((b)->info._size & ZEND_MM_USED_BLOCK)
#define ZEND_MM_IS_GUARD_BLOCK(b)		(((b)->info._size & ZEND_MM_TYPE_MASK) == ZEND_MM_GUARD_BLOCK)

#define ZEND_MM_NEXT_BLOCK(b)			ZEND_MM_BLOCK_AT(b, ZEND_MM_BLOCK_SIZE(b))
#define ZEND_MM_PREV_BLOCK(b)			ZEND_MM_BLOCK_AT(b, -(ssize_t)((b)->info._prev & ~ZEND_MM_TYPE_MASK))

#define ZEND_MM_PREV_BLOCK_IS_FREE(b)	(!((b)->info._prev & ZEND_MM_USED_BLOCK))

#define ZEND_MM_MARK_FIRST_BLOCK(b)		((b)->info._prev = ZEND_MM_GUARD_BLOCK)
#define ZEND_MM_IS_FIRST_BLOCK(b)		((b)->info._prev == ZEND_MM_GUARD_BLOCK)

/* optimized access */
#define ZEND_MM_FREE_BLOCK_SIZE(b)		(b)->info._size

/* Aligned header size */
 	//block头部大小 = 16bytes/64
#define ZEND_MM_ALIGNED_HEADER_SIZE			ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_block)) //_prev + _size
 	//空闲block头部大小 = 32bytes/64
#define ZEND_MM_ALIGNED_FREE_HEADER_SIZE	ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_small_free_block))
 	//已分配block头部大小 = 16bytes/64
#define ZEND_MM_MIN_ALLOC_BLOCK_SIZE		ZEND_MM_ALIGNED_SIZE(ZEND_MM_ALIGNED_HEADER_SIZE + END_MAGIC_SIZE) //END_MAGIC_SIZE = 0
 	//至少给block头部预留大小 = 32bytes/64
#define ZEND_MM_ALIGNED_MIN_HEADER_SIZE		(ZEND_MM_MIN_ALLOC_BLOCK_SIZE>ZEND_MM_ALIGNED_FREE_HEADER_SIZE?ZEND_MM_MIN_ALLOC_BLOCK_SIZE:ZEND_MM_ALIGNED_FREE_HEADER_SIZE)
 	//段大小 = 16bytes/64
#define ZEND_MM_ALIGNED_SEGMENT_SIZE		ZEND_MM_ALIGNED_SIZE(sizeof(zend_mm_segment))
 	// sizeof(zend_mm_small_free_block) - sizeof(zend_mm_block) = 2 pointer = 16bytes/64
#define ZEND_MM_MIN_SIZE					((ZEND_MM_ALIGNED_MIN_HEADER_SIZE>(ZEND_MM_ALIGNED_HEADER_SIZE+END_MAGIC_SIZE))?(ZEND_MM_ALIGNED_MIN_HEADER_SIZE-(ZEND_MM_ALIGNED_HEADER_SIZE+END_MAGIC_SIZE)):0)
 	// 64 * 8 + ZEND_MM_ALIGNED_MIN_HEADER_SIZE = 544bytes/64
#define ZEND_MM_MAX_SMALL_SIZE				((ZEND_MM_NUM_BUCKETS<<ZEND_MM_ALIGNMENT_LOG2)+ZEND_MM_ALIGNED_MIN_HEADER_SIZE)
 	//size小于16字节，返回32字节，否则返回size+16字节block头
#define ZEND_MM_TRUE_SIZE(size)				((size<ZEND_MM_MIN_SIZE)?(ZEND_MM_ALIGNED_MIN_HEADER_SIZE):(ZEND_MM_ALIGNED_SIZE(size+ZEND_MM_ALIGNED_HEADER_SIZE+END_MAGIC_SIZE)))
 	//( true_size - ZEND_MM_ALIGNED_MIN_HEADER_SIZE ) / 2^3
#define ZEND_MM_BUCKET_INDEX(true_size)		((true_size>>ZEND_MM_ALIGNMENT_LOG2)-(ZEND_MM_ALIGNED_MIN_HEADER_SIZE>>ZEND_MM_ALIGNMENT_LOG2))
 	//小于小块内存大小 32bytes/64 <= true_size <= 536bytes/64
#define ZEND_MM_SMALL_SIZE(true_size)		(true_size < ZEND_MM_MAX_SMALL_SIZE)

/* Memory calculations */
 	//blk指针移动offset个字节
#define ZEND_MM_BLOCK_AT(blk, offset)	((zend_mm_block *) (((char *) (blk))+(offset)))
 	//移到数据内存开始位置，prev_free_block和next_free_block都用作用户数据存储
#define ZEND_MM_DATA_OF(p)				((void *) (((char *) (p))+ZEND_MM_ALIGNED_HEADER_SIZE))
 	//移动到block信息头部
#define ZEND_MM_HEADER_OF(blk)			ZEND_MM_BLOCK_AT(blk, -(int)ZEND_MM_ALIGNED_HEADER_SIZE)

/* Debug output */
#if ZEND_DEBUG

# ifdef ZTS
#  define ZEND_MM_SET_THREAD_ID(block) \
	((zend_mm_block*)(block))->thread_id = tsrm_thread_id()
#  define ZEND_MM_BAD_THREAD_ID(block) ((block)->thread_id != tsrm_thread_id())
# else
#  define ZEND_MM_SET_THREAD_ID(block)
#  define ZEND_MM_BAD_THREAD_ID(block) 0
# endif

# define ZEND_MM_VALID_PTR(block) \
	zend_mm_check_ptr(heap, block, 1 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC)

# define ZEND_MM_SET_MAGIC(block, val) do { \
		(block)->magic = (val); \
	} while (0)

# define ZEND_MM_CHECK_MAGIC(block, val) do { \
		if ((block)->magic != (val)) { \
			zend_mm_panic("zend_mm_heap corrupted"); \
		} \
	} while (0)

# define ZEND_MM_SET_DEBUG_INFO(block, __size, set_valid, set_thread) do { \
		((zend_mm_block*)(block))->debug.filename = __zend_filename; \
		((zend_mm_block*)(block))->debug.lineno = __zend_lineno; \
		((zend_mm_block*)(block))->debug.orig_filename = __zend_orig_filename; \
		((zend_mm_block*)(block))->debug.orig_lineno = __zend_orig_lineno; \
		ZEND_MM_SET_BLOCK_SIZE(block, __size); \
		if (set_valid) { \
			ZEND_MM_SET_MAGIC(block, MEM_BLOCK_VALID); \
		} \
		if (set_thread) { \
			ZEND_MM_SET_THREAD_ID(block); \
		} \
	} while (0)

#else

# define ZEND_MM_VALID_PTR(ptr) EXPECTED(ptr != NULL)

# define ZEND_MM_SET_MAGIC(block, val)

# define ZEND_MM_CHECK_MAGIC(block, val)

# define ZEND_MM_SET_DEBUG_INFO(block, __size, set_valid, set_thread) ZEND_MM_SET_BLOCK_SIZE(block, __size)

#endif


#if ZEND_MM_HEAP_PROTECTION

# define ZEND_MM_CHECK_PROTECTION(block) \
	do { \
		if ((block)->debug.start_magic != _mem_block_start_magic || \
		    memcmp(ZEND_MM_END_MAGIC_PTR(block), &_mem_block_end_magic, END_MAGIC_SIZE) != 0) { \
		    zend_mm_panic("zend_mm_heap corrupted"); \
		} \
	} while (0)

# define ZEND_MM_END_MAGIC_PTR(block) \
	(((char*)(ZEND_MM_DATA_OF(block))) + ((zend_mm_block*)(block))->debug.size)

# define END_MAGIC_SIZE sizeof(unsigned int)

# define ZEND_MM_SET_BLOCK_SIZE(block, __size) do { \
		char *p; \
		((zend_mm_block*)(block))->debug.size = (__size); \
		p = ZEND_MM_END_MAGIC_PTR(block); \
		((zend_mm_block*)(block))->debug.start_magic = _mem_block_start_magic; \
		memcpy(p, &_mem_block_end_magic, END_MAGIC_SIZE); \
	} while (0)

static unsigned int _mem_block_start_magic = 0;
static unsigned int _mem_block_end_magic   = 0;

#else

# if ZEND_DEBUG
#  define ZEND_MM_SET_BLOCK_SIZE(block, _size) \
	((zend_mm_block*)(block))->debug.size = (_size)
# else
#  define ZEND_MM_SET_BLOCK_SIZE(block, _size)
# endif

# define ZEND_MM_CHECK_PROTECTION(block)

# define END_MAGIC_SIZE 0

#endif

#if ZEND_MM_SAFE_UNLINKING
# define ZEND_MM_CHECK_BLOCK_LINKAGE(block) \
	if (UNEXPECTED((block)->info._size != ZEND_MM_BLOCK_AT(block, ZEND_MM_FREE_BLOCK_SIZE(block))->info._prev) || \
		UNEXPECTED(!UNEXPECTED(ZEND_MM_IS_FIRST_BLOCK(block)) && \
	    UNEXPECTED(ZEND_MM_PREV_BLOCK(block)->info._size != (block)->info._prev))) { \
	    zend_mm_panic("zend_mm_heap corrupted"); \
	}
#define ZEND_MM_CHECK_TREE(block) \
	if (UNEXPECTED(*((block)->parent) != (block))) { \
		zend_mm_panic("zend_mm_heap corrupted"); \
	}
#else
# define ZEND_MM_CHECK_BLOCK_LINKAGE(block)
# define ZEND_MM_CHECK_TREE(block)
#endif

#define ZEND_MM_LARGE_BUCKET_INDEX(S) zend_mm_high_bit(S)

static void *_zend_mm_alloc_int(zend_mm_heap *heap, size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC) ZEND_ATTRIBUTE_MALLOC ZEND_ATTRIBUTE_ALLOC_SIZE(2);
static void _zend_mm_free_int(zend_mm_heap *heap, void *p ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC);
static void *_zend_mm_realloc_int(zend_mm_heap *heap, void *p, size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC) ZEND_ATTRIBUTE_ALLOC_SIZE(3);

static inline unsigned int zend_mm_high_bit(size_t _size)
{
#if defined(__GNUC__) && (defined(__native_client__) || defined(i386))
	unsigned int n;

	__asm__("bsrl %1,%0\n\t" : "=r" (n) : "rm"  (_size) : "cc");
	return n;
#elif defined(__GNUC__) && defined(__x86_64__)
	unsigned long n;

        __asm__("bsr %1,%0\n\t" : "=r" (n) : "rm"  (_size) : "cc");
        return (unsigned int)n;
#elif defined(_MSC_VER) && defined(_M_IX86)
	__asm {
		bsr eax, _size
	}
#elif defined(__GNUC__) && (defined(__arm__) ||  defined(__aarch64__))
	return (8 * SIZEOF_SIZE_T - 1) - __builtin_clzl(_size);	//返回最高位1所在位数-1
#else
	unsigned int n = 0;
	while (_size != 0) {
		_size = _size >> 1;
		n++;
	}
	return n-1;
#endif
}

static inline unsigned int zend_mm_low_bit(size_t _size)
{
#if defined(__GNUC__) && (defined(__native_client__) || defined(i386))
	unsigned int n;

	__asm__("bsfl %1,%0\n\t" : "=r" (n) : "rm"  (_size) : "cc");
	return n;
#elif defined(__GNUC__) && defined(__x86_64__)
        unsigned long n;

        __asm__("bsf %1,%0\n\t" : "=r" (n) : "rm"  (_size) : "cc");
        return (unsigned int)n;
#elif defined(_MSC_VER) && defined(_M_IX86)
	__asm {
		bsf eax, _size
   }
#elif defined(__GNUC__) && (defined(__arm__) || defined(__aarch64__))
	return __builtin_ctzl(_size);  //返回最低位1后0的个数
#else
	static const int offset[16] = {4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0};
	unsigned int n;
	unsigned int index = 0;

	n = offset[_size & 15];
	while (n == 4) {
		_size >>= 4;
		index += n;
		n = offset[_size & 15];
	}

	return index + n;
#endif
}

static inline void zend_mm_add_to_free_list(zend_mm_heap *heap, zend_mm_free_block *mm_block)
{
	size_t size;
	size_t index;

	ZEND_MM_SET_MAGIC(mm_block, MEM_BLOCK_FREED);

	size = ZEND_MM_FREE_BLOCK_SIZE(mm_block);
	if (EXPECTED(!ZEND_MM_SMALL_SIZE(size))) {  //大块内存，插入到large_free_buckets
		zend_mm_free_block **p;

		index = ZEND_MM_LARGE_BUCKET_INDEX(size);  //根据最高位1的位数确定index
		p = &heap->large_free_buckets[index];  //寻找插入位置
		mm_block->child[0] = mm_block->child[1] = NULL; //只会插入到2类地方，无论是插入到叶子节点还是插入到树节点链表中，都是没有左右孩子的
		if (!*p) {  //头指针指向空，mm_block插入作为头节点
			*p = mm_block;
			mm_block->parent = p; //双亲是p
			mm_block->prev_free_block = mm_block->next_free_block = mm_block; //链表第一个节点
			heap->large_free_bitmap |= (ZEND_MM_LONG_CONST(1) << index); //这个位置有空闲块了，标记一下
		} else {
			size_t m;
			//将最高位移到最左边，每次循环左移1位
			for (m = size << (ZEND_MM_NUM_BUCKETS - index); ; m <<= 1) {
				zend_mm_free_block *prev = *p;

				if (ZEND_MM_FREE_BLOCK_SIZE(prev) != size) { //没有找到大小为size的节点
					//通过对应位是0还是1决定走左孩子还是右孩子
					p = &prev->child[(m >> (ZEND_MM_NUM_BUCKETS-1)) & 1];
					if (!*p) { //prev已经是叶子节点了
						*p = mm_block; //mm_block挂到prev的左孩子或右孩子上成为叶子节点
						mm_block->parent = p; //父指针指向左孩子或右孩子地址
						mm_block->prev_free_block = mm_block->next_free_block = mm_block; //链表第一个节点
						break;
					}
				} else { //找到大小为size的节点
					zend_mm_free_block *next = prev->next_free_block;
					//头插法插入进去
					prev->next_free_block = next->prev_free_block = mm_block;
					mm_block->next_free_block = next;
					mm_block->prev_free_block = prev;
					mm_block->parent = NULL;
					break;
				}
			}
		}
	} else {  //小块内存，插入到free_buckets
		zend_mm_free_block *prev, *next;

		index = ZEND_MM_BUCKET_INDEX(size); //根据大小计算对应free_buckets的下标

		prev = ZEND_MM_SMALL_FREE_BUCKET(heap, index); //取得free_buckets[index]
		if (prev->prev_free_block == prev) {	//循环链表指向它自己，说明此时没有其他节点
			heap->free_bitmap |= (ZEND_MM_LONG_CONST(1) << index);	//将位图对应位标记为1，表示该位置挂有空闲节点
		}
		next = prev->next_free_block;
		//头插法插入
		mm_block->prev_free_block = prev;
		mm_block->next_free_block = next;
		prev->next_free_block = next->prev_free_block = mm_block;
	}
}

static inline void zend_mm_remove_from_free_list(zend_mm_heap *heap, zend_mm_free_block *mm_block)
{
	zend_mm_free_block *prev = mm_block->prev_free_block;
	zend_mm_free_block *next = mm_block->next_free_block;

	ZEND_MM_CHECK_MAGIC(mm_block, MEM_BLOCK_FREED);

	if (EXPECTED(prev == mm_block)) {  //只有在树节点中，mm_block->prev_free_block会指向mm_block，链表上唯一一个节点
		zend_mm_free_block **rp, **cp;

#if ZEND_MM_SAFE_UNLINKING
		if (UNEXPECTED(next != mm_block)) {
			zend_mm_panic("zend_mm_heap corrupted");
		}
#endif

		rp = &mm_block->child[mm_block->child[1] != NULL];  //右孩子不为空的话，rp指向右孩子，否则指向左孩子
		prev = *rp;
		if (EXPECTED(prev == NULL)) {  //左右孩子都为空
			size_t index = ZEND_MM_LARGE_BUCKET_INDEX(ZEND_MM_FREE_BLOCK_SIZE(mm_block));

			ZEND_MM_CHECK_TREE(mm_block);
			*mm_block->parent = NULL; //parent指向父节点左右孩子之一，改变左右孩子指向
			if (mm_block->parent == &heap->large_free_buckets[index]) { //如果mm_block是整棵树的根节点
				heap->large_free_bitmap &= ~(ZEND_MM_LONG_CONST(1) << index); //位图标记下这个位置没有空闲块了
		    }
		} else { //左或右孩子不为空
			while (*(cp = &(prev->child[prev->child[1] != NULL])) != NULL) {  //一直遍历到叶子
				prev = *cp;
				rp = cp;
			}
			*rp = NULL;
			//上面这段代码是一直遍历到叶子，下面代码是拆下叶子来填补mm_block
subst_block:
			ZEND_MM_CHECK_TREE(mm_block);
			*mm_block->parent = prev; //mm_block父节点的孩子指向prev
			prev->parent = mm_block->parent;
			if ((prev->child[0] = mm_block->child[0])) { //prev链接mm_block的左孩子
				ZEND_MM_CHECK_TREE(prev->child[0]);
				prev->child[0]->parent = &prev->child[0];
			}
			if ((prev->child[1] = mm_block->child[1])) { //prev链接mm_block的右孩子
				ZEND_MM_CHECK_TREE(prev->child[1]);
				prev->child[1]->parent = &prev->child[1];
			}
		}
	} else {

#if ZEND_MM_SAFE_UNLINKING
		if (UNEXPECTED(prev->next_free_block != mm_block) || UNEXPECTED(next->prev_free_block != mm_block)) {
			zend_mm_panic("zend_mm_heap corrupted");
		}
#endif
		//为于large_free_buckets树节点链表中的节点也这样拆除
		prev->next_free_block = next;  //维护链表
		next->prev_free_block = prev;

		if (EXPECTED(ZEND_MM_SMALL_SIZE(ZEND_MM_FREE_BLOCK_SIZE(mm_block)))) {  //小块内存
			if (EXPECTED(prev == next)) {  //指向自己，说明是free_buckets[index]，没有空闲块了
				size_t index = ZEND_MM_BUCKET_INDEX(ZEND_MM_FREE_BLOCK_SIZE(mm_block));

				if (EXPECTED(heap->free_buckets[index*2] == heap->free_buckets[index*2+1])) {
					heap->free_bitmap &= ~(ZEND_MM_LONG_CONST(1) << index);  //位图标记下这个位置没有空闲块了
				}
			}
		} else if (UNEXPECTED(mm_block->parent == ZEND_MM_REST_BLOCK)) {  //如果mm_block挂在rest
			heap->rest_count--;
		} else if (UNEXPECTED(mm_block->parent != NULL)) {  //mm_block是子树根
			goto subst_block;
		}
	}
}
//将块添加到rest链表
static inline void zend_mm_add_to_rest_list(zend_mm_heap *heap, zend_mm_free_block *mm_block)
{
	zend_mm_free_block *prev, *next;

	while (heap->rest_count >= ZEND_MM_MAX_REST_BLOCKS) {  //16个
		zend_mm_free_block *p = heap->rest_buckets[1];

		if (!ZEND_MM_SMALL_SIZE(ZEND_MM_FREE_BLOCK_SIZE(p))) {  //最多挂16个large_free_block
			heap->rest_count--;
		}
		prev = p->prev_free_block;
		next = p->next_free_block;
		prev->next_free_block = next;
		next->prev_free_block = prev;
		zend_mm_add_to_free_list(heap, p);  //将block从rest取下来，挂到free_bucket或large_free_bucket上
	}

	if (!ZEND_MM_SMALL_SIZE(ZEND_MM_FREE_BLOCK_SIZE(mm_block))) { //大空闲块
		mm_block->parent = ZEND_MM_REST_BLOCK;  //标志
		heap->rest_count++;
	}

	ZEND_MM_SET_MAGIC(mm_block, MEM_BLOCK_FREED);
	//注意，这里是尾插法插入
	prev = heap->rest_buckets[0];
	next = prev->next_free_block;
	mm_block->prev_free_block = prev;
	mm_block->next_free_block = next;
	prev->next_free_block = next->prev_free_block = mm_block;
}

static inline void zend_mm_init(zend_mm_heap *heap)
{
	zend_mm_free_block* p;
	int i;

	heap->free_bitmap = 0;   //小块位图每个位设为0
	heap->large_free_bitmap = 0;  //大块位图每个位设为0
#if ZEND_MM_CACHE
	heap->cached = 0;	//缓存大小
	memset(heap->cache, 0, sizeof(heap->cache)); //指针指向NULL
#endif
#if ZEND_MM_CACHE_STAT
	for (i = 0; i < ZEND_MM_NUM_BUCKETS; i++) {
		heap->cache_stat[i].count = 0;   //每个cache挂载的block计数
	}
#endif
	p = ZEND_MM_SMALL_FREE_BUCKET(heap, 0);	//初始化小块内存列表
	for (i = 0; i < ZEND_MM_NUM_BUCKETS; i++) {
		p->next_free_block = p;	//循环链表初始化
		p->prev_free_block = p; //循环链表初始化
		p = (zend_mm_free_block*)((char*)p + sizeof(zend_mm_free_block*) * 2);	//后移2个指针
		heap->large_free_buckets[i] = NULL;		//初始化大块内存列表
	}
	heap->rest_buckets[0] = heap->rest_buckets[1] = ZEND_MM_REST_BUCKET(heap); //初始化rest内存列表
	heap->rest_count = 0;	//rest挂载block数量
}

static void zend_mm_del_segment(zend_mm_heap *heap, zend_mm_segment *segment)
{
	zend_mm_segment **p = &heap->segments_list;

	while (*p != segment) {  //在链表中找到要释放的段
		p = &(*p)->next_segment;
	}
	*p = segment->next_segment;  //维护链表
	heap->real_size -= segment->size;  //真实占用内存大小
	ZEND_MM_STORAGE_FREE(segment);  //释放
}

#if ZEND_MM_CACHE
static void zend_mm_free_cache(zend_mm_heap *heap)   //释放缓存块
{
	int i;

	for (i = 0; i < ZEND_MM_NUM_BUCKETS; i++) {  //遍历缓存数组
		if (heap->cache[i]) {
			zend_mm_free_block *mm_block = heap->cache[i];

			while (mm_block) {
				size_t size = ZEND_MM_BLOCK_SIZE(mm_block);
				zend_mm_free_block *q = mm_block->prev_free_block;
				zend_mm_block *next_block = ZEND_MM_NEXT_BLOCK(mm_block);

				heap->cached -= size;
				//合并物理相邻空闲内存
				if (ZEND_MM_PREV_BLOCK_IS_FREE(mm_block)) {
					mm_block = (zend_mm_free_block*)ZEND_MM_PREV_BLOCK(mm_block);
					size += ZEND_MM_FREE_BLOCK_SIZE(mm_block);
					zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) mm_block);
				}
				if (ZEND_MM_IS_FREE_BLOCK(next_block)) {
					size += ZEND_MM_FREE_BLOCK_SIZE(next_block);
					zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) next_block);
				}
				ZEND_MM_BLOCK(mm_block, ZEND_MM_FREE_BLOCK, size);

				if (ZEND_MM_IS_FIRST_BLOCK(mm_block) &&
				    ZEND_MM_IS_GUARD_BLOCK(ZEND_MM_NEXT_BLOCK(mm_block))) {
					zend_mm_del_segment(heap, (zend_mm_segment *) ((char *)mm_block - ZEND_MM_ALIGNED_SEGMENT_SIZE));
				} else {
					zend_mm_add_to_free_list(heap, (zend_mm_free_block *) mm_block);
				}

				mm_block = q;
			}
			heap->cache[i] = NULL;
#if ZEND_MM_CACHE_STAT
			heap->cache_stat[i].count = 0;
#endif
		}
	}
}
#endif

#if ZEND_MM_HEAP_PROTECTION || ZEND_MM_COOKIES
static void zend_mm_random(unsigned char *buf, size_t size) /* {{{ */
{
	size_t i = 0;
	unsigned char t;

#ifdef ZEND_WIN32
	HCRYPTPROV   hCryptProv;
	int has_context = 0;

	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
		/* Could mean that the key container does not exist, let try 
		   again by asking for a new one */
		if (GetLastError() == NTE_BAD_KEYSET) {
			if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
				has_context = 1;
			}
		}
	} else {
		has_context = 1;
	}
	if (has_context) {
		do {
			BOOL ret = CryptGenRandom(hCryptProv, size, buf);
			CryptReleaseContext(hCryptProv, 0);
			if (ret) {
				while (i < size && buf[i] != 0) {
					i++;
				}
				if (i == size) {
					return;
				}
		   }
		} while (0);
	}
#elif defined(HAVE_DEV_URANDOM)
	int fd = open("/dev/urandom", 0);

	if (fd >= 0) {
		if (read(fd, buf, size) == size) {
			while (i < size && buf[i] != 0) {
				i++;
			}
			if (i == size) {
				close(fd);
			    return;
			}
		}
		close(fd);
	}
#endif
	t = (unsigned char)getpid();
	while (i < size) {
		do {
			buf[i] = ((unsigned char)rand()) ^ t;
		} while (buf[i] == 0);
		t = buf[i++] << 1;
    }
}
/* }}} */
#endif

/* Notes:
 * - This function may alter the block_sizes values to match platform alignment
 * - This function does *not* perform sanity checks on the arguments
 */
ZEND_API zend_mm_heap *zend_mm_startup_ex(const zend_mm_mem_handlers *handlers, size_t block_size, size_t reserve_size, int internal, void *params)
{
	zend_mm_storage *storage;
	zend_mm_heap    *heap;

#if 0
	int i;

	printf("ZEND_MM_ALIGNMENT=%d\n", ZEND_MM_ALIGNMENT);
	printf("ZEND_MM_ALIGNMENT_LOG2=%d\n", ZEND_MM_ALIGNMENT_LOG2);
	printf("ZEND_MM_MIN_SIZE=%d\n", ZEND_MM_MIN_SIZE);
	printf("ZEND_MM_MAX_SMALL_SIZE=%d\n", ZEND_MM_MAX_SMALL_SIZE);
	printf("ZEND_MM_ALIGNED_HEADER_SIZE=%d\n", ZEND_MM_ALIGNED_HEADER_SIZE);
	printf("ZEND_MM_ALIGNED_FREE_HEADER_SIZE=%d\n", ZEND_MM_ALIGNED_FREE_HEADER_SIZE);
	printf("ZEND_MM_MIN_ALLOC_BLOCK_SIZE=%d\n", ZEND_MM_MIN_ALLOC_BLOCK_SIZE);
	printf("ZEND_MM_ALIGNED_MIN_HEADER_SIZE=%d\n", ZEND_MM_ALIGNED_MIN_HEADER_SIZE);
	printf("ZEND_MM_ALIGNED_SEGMENT_SIZE=%d\n", ZEND_MM_ALIGNED_SEGMENT_SIZE);
	for (i = 0; i < ZEND_MM_MAX_SMALL_SIZE; i++) {
		printf("%3d%c: %3ld %d %2ld\n", i, (i == ZEND_MM_MIN_SIZE?'*':' '), (long)ZEND_MM_TRUE_SIZE(i), ZEND_MM_SMALL_SIZE(ZEND_MM_TRUE_SIZE(i)), (long)ZEND_MM_BUCKET_INDEX(ZEND_MM_TRUE_SIZE(i)));
	}
	exit(0);
#endif

#if ZEND_MM_HEAP_PROTECTION
	if (_mem_block_start_magic == 0) {
		zend_mm_random((unsigned char*)&_mem_block_start_magic, sizeof(_mem_block_start_magic));
	}
	if (_mem_block_end_magic == 0) {
		zend_mm_random((unsigned char*)&_mem_block_end_magic, sizeof(_mem_block_end_magic));
	}
#endif
#if ZEND_MM_COOKIES
	if (_zend_mm_cookie == 0) {
		zend_mm_random((unsigned char*)&_zend_mm_cookie, sizeof(_zend_mm_cookie));
	}
#endif

	if (zend_mm_low_bit(block_size) != zend_mm_high_bit(block_size)) {
		fprintf(stderr, "'block_size' must be a power of two\n");
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
		fflush(stderr);
#endif
		exit(255);
	}
	storage = handlers->init(params);
	if (!storage) {
		fprintf(stderr, "Cannot initialize zend_mm storage [%s]\n", handlers->name);
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
		fflush(stderr);
#endif
		exit(255);
	}
	storage->handlers = handlers;

	heap = malloc(sizeof(struct _zend_mm_heap));
	if (heap == NULL) {
		fprintf(stderr, "Cannot allocate heap for zend_mm storage [%s]\n", handlers->name);
#ifdef PHP_WIN32
		fflush(stderr);
#endif
		exit(255);
	}
	heap->storage = storage;
	heap->block_size = block_size;
	heap->compact_size = 0;
	heap->segments_list = NULL;
	zend_mm_init(heap);
# if ZEND_MM_CACHE_STAT
	memset(heap->cache_stat, 0, sizeof(heap->cache_stat));
# endif

	heap->use_zend_alloc = 1;
	heap->real_size = 0;
	heap->overflow = 0;
	heap->real_peak = 0;
	heap->limit = ZEND_MM_LONG_CONST(1)<<(ZEND_MM_NUM_BUCKETS-2); //2^62 内存四分之一  
	heap->size = 0;
	heap->peak = 0;
	heap->internal = internal;
	heap->reserve = NULL;
	heap->reserve_size = reserve_size;
	/* 储备一些空间，当内存溢出时用以错误报告，8 * 1024 = 8k */
	if (reserve_size > 0) {
		heap->reserve = _zend_mm_alloc_int(heap, reserve_size ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC);
	}
	if (internal) {
		int i;
		zend_mm_free_block *p, *q, *orig;
		zend_mm_heap *mm_heap = _zend_mm_alloc_int(heap, sizeof(zend_mm_heap)  ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC);

		*mm_heap = *heap;

		p = ZEND_MM_SMALL_FREE_BUCKET(mm_heap, 0);
		orig = ZEND_MM_SMALL_FREE_BUCKET(heap, 0);
		for (i = 0; i < ZEND_MM_NUM_BUCKETS; i++) {
			q = p;
			while (q->prev_free_block != orig) {
				q = q->prev_free_block;
			}
			q->prev_free_block = p;
			q = p;
			while (q->next_free_block != orig) {
				q = q->next_free_block;
			}
			q->next_free_block = p;
			p = (zend_mm_free_block*)((char*)p + sizeof(zend_mm_free_block*) * 2);
			orig = (zend_mm_free_block*)((char*)orig + sizeof(zend_mm_free_block*) * 2);
			if (mm_heap->large_free_buckets[i]) {
				mm_heap->large_free_buckets[i]->parent = &mm_heap->large_free_buckets[i];
			}
		}
		mm_heap->rest_buckets[0] = mm_heap->rest_buckets[1] = ZEND_MM_REST_BUCKET(mm_heap);
		mm_heap->rest_count = 0;

		free(heap);
		heap = mm_heap;
	}
	return heap;
}

ZEND_API zend_mm_heap *zend_mm_startup(void)
{
	int i;
	size_t seg_size;
	char *mem_type = getenv("ZEND_MM_MEM_TYPE"); 	/*获取系统环境变量*/
	char *tmp;
	const zend_mm_mem_handlers *handlers;
	zend_mm_heap *heap;

	if (mem_type == NULL) {
		i = 0;
	} else {
		for (i = 0; mem_handlers[i].name; i++) {
			if (strcmp(mem_handlers[i].name, mem_type) == 0) {
				break;
			}
		}
		if (!mem_handlers[i].name) {
			fprintf(stderr, "Wrong or unsupported zend_mm storage type '%s'\n", mem_type);
			fprintf(stderr, "  supported types:\n");
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
			fflush(stderr);
#endif
			for (i = 0; mem_handlers[i].name; i++) {
				fprintf(stderr, "    '%s'\n", mem_handlers[i].name);
			}
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
			fflush(stderr);
#endif
			exit(255);
		}
	}
	handlers = &mem_handlers[i];

	tmp = getenv("ZEND_MM_SEG_SIZE");
	if (tmp) {
		seg_size = zend_atoi(tmp, 0);
		if (zend_mm_low_bit(seg_size) != zend_mm_high_bit(seg_size)) {
			fprintf(stderr, "ZEND_MM_SEG_SIZE must be a power of two\n");
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
			fflush(stderr);
#endif
			exit(255);
		} else if (seg_size < ZEND_MM_ALIGNED_SEGMENT_SIZE + ZEND_MM_ALIGNED_HEADER_SIZE) {
			fprintf(stderr, "ZEND_MM_SEG_SIZE is too small\n");
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
			fflush(stderr);
#endif
			exit(255);
		}
	} else {
		seg_size = ZEND_MM_SEG_SIZE;
	}

	heap = zend_mm_startup_ex(handlers, seg_size, ZEND_MM_RESERVE_SIZE, 0, NULL);
	if (heap) {
		tmp = getenv("ZEND_MM_COMPACT");
		if (tmp) {
			heap->compact_size = zend_atoi(tmp, 0);
		} else {
			heap->compact_size = 2 * 1024 * 1024;
		}
	}
	return heap;
}

#if ZEND_DEBUG
static long zend_mm_find_leaks(zend_mm_segment *segment, zend_mm_block *b)
{
	long leaks = 0;
	zend_mm_block *p, *q;

	p = ZEND_MM_NEXT_BLOCK(b);
	while (1) {
		if (ZEND_MM_IS_GUARD_BLOCK(p)) {
			ZEND_MM_CHECK_MAGIC(p, MEM_BLOCK_GUARD);
			segment = segment->next_segment;
			if (!segment) {
				break;
			}
			p = (zend_mm_block *) ((char *) segment + ZEND_MM_ALIGNED_SEGMENT_SIZE);
			continue;
		}
		q = ZEND_MM_NEXT_BLOCK(p);
		if (q <= p ||
		    (char*)q > (char*)segment + segment->size ||
		    p->info._size != q->info._prev) {
		    zend_mm_panic("zend_mm_heap corrupted");
		}
		if (!ZEND_MM_IS_FREE_BLOCK(p)) {
			if (p->magic == MEM_BLOCK_VALID) {
				if (p->debug.filename==b->debug.filename && p->debug.lineno==b->debug.lineno) {
					ZEND_MM_SET_MAGIC(p, MEM_BLOCK_LEAK);
					leaks++;
				}
#if ZEND_MM_CACHE
			} else if (p->magic == MEM_BLOCK_CACHED) {
				/* skip it */
#endif
			} else if (p->magic != MEM_BLOCK_LEAK) {
			    zend_mm_panic("zend_mm_heap corrupted");
			}
		}
		p = q;
	}
	return leaks;
}

static void zend_mm_check_leaks(zend_mm_heap *heap TSRMLS_DC)
{
	zend_mm_segment *segment = heap->segments_list;
	zend_mm_block *p, *q;
	zend_uint total = 0;

	if (!segment) {
		return;
	}
	p = (zend_mm_block *) ((char *) segment + ZEND_MM_ALIGNED_SEGMENT_SIZE);
	while (1) {
		q = ZEND_MM_NEXT_BLOCK(p);
		if (q <= p ||
		    (char*)q > (char*)segment + segment->size ||
		    p->info._size != q->info._prev) {
			zend_mm_panic("zend_mm_heap corrupted");
		}
		if (!ZEND_MM_IS_FREE_BLOCK(p)) {
			if (p->magic == MEM_BLOCK_VALID) {
				long repeated;
				zend_leak_info leak;

				ZEND_MM_SET_MAGIC(p, MEM_BLOCK_LEAK);

				leak.addr = ZEND_MM_DATA_OF(p);
				leak.size = p->debug.size;
				leak.filename = p->debug.filename;
				leak.lineno = p->debug.lineno;
				leak.orig_filename = p->debug.orig_filename;
				leak.orig_lineno = p->debug.orig_lineno;

				zend_message_dispatcher(ZMSG_LOG_SCRIPT_NAME, NULL TSRMLS_CC);
				zend_message_dispatcher(ZMSG_MEMORY_LEAK_DETECTED, &leak TSRMLS_CC);
				repeated = zend_mm_find_leaks(segment, p);
				total += 1 + repeated;
				if (repeated) {
					zend_message_dispatcher(ZMSG_MEMORY_LEAK_REPEATED, (void *)(zend_uintptr_t)repeated TSRMLS_CC);
				}
#if ZEND_MM_CACHE
			} else if (p->magic == MEM_BLOCK_CACHED) {
				/* skip it */
#endif
			} else if (p->magic != MEM_BLOCK_LEAK) {
				zend_mm_panic("zend_mm_heap corrupted");
			}
		}
		if (ZEND_MM_IS_GUARD_BLOCK(q)) {
			segment = segment->next_segment;
			if (!segment) {
				break;
			}
			q = (zend_mm_block *) ((char *) segment + ZEND_MM_ALIGNED_SEGMENT_SIZE);
		}
		p = q;
	}
	if (total) {
		zend_message_dispatcher(ZMSG_MEMORY_LEAKS_GRAND_TOTAL, &total TSRMLS_CC);
	}
}

static int zend_mm_check_ptr(zend_mm_heap *heap, void *ptr, int silent ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_block *p;
	int no_cache_notice = 0;
	int had_problems = 0;
	int valid_beginning = 1;

	if (silent==2) {
		silent = 1;
		no_cache_notice = 1;
	} else if (silent==3) {
		silent = 0;
		no_cache_notice = 1;
	}
	if (!silent) {
		TSRMLS_FETCH();
		
		zend_message_dispatcher(ZMSG_LOG_SCRIPT_NAME, NULL TSRMLS_CC);
		zend_debug_alloc_output("---------------------------------------\n");
		zend_debug_alloc_output("%s(%d) : Block "PTR_FMT" status:\n" ZEND_FILE_LINE_RELAY_CC, ptr);
		if (__zend_orig_filename) {
			zend_debug_alloc_output("%s(%d) : Actual location (location was relayed)\n" ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
		if (!ptr) {
			zend_debug_alloc_output("NULL\n");
			zend_debug_alloc_output("---------------------------------------\n");
			return 0;
		}
	}

	if (!ptr) {
		if (silent) {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	}

	p = ZEND_MM_HEADER_OF(ptr);

#ifdef ZTS
	if (ZEND_MM_BAD_THREAD_ID(p)) {
		if (!silent) {
			zend_debug_alloc_output("Invalid pointer: ((thread_id=0x%0.8X) != (expected=0x%0.8X))\n", (long)p->thread_id, (long)tsrm_thread_id());
			had_problems = 1;
		} else {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	}
#endif

	if (p->info._size != ZEND_MM_NEXT_BLOCK(p)->info._prev) {
		if (!silent) {
			zend_debug_alloc_output("Invalid pointer: ((size="PTR_FMT") != (next.prev="PTR_FMT"))\n", p->info._size, ZEND_MM_NEXT_BLOCK(p)->info._prev);
			had_problems = 1;
		} else {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	}
	if (p->info._prev != ZEND_MM_GUARD_BLOCK &&
	    ZEND_MM_PREV_BLOCK(p)->info._size != p->info._prev) {
		if (!silent) {
			zend_debug_alloc_output("Invalid pointer: ((prev="PTR_FMT") != (prev.size="PTR_FMT"))\n", p->info._prev, ZEND_MM_PREV_BLOCK(p)->info._size);
			had_problems = 1;
		} else {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	}

	if (had_problems) {
		zend_debug_alloc_output("---------------------------------------\n");
		return 0;
	}

	if (!silent) {
		zend_debug_alloc_output("%10s\t","Beginning:  ");
	}

	if (!ZEND_MM_IS_USED_BLOCK(p)) {
		if (!silent) {
			if (p->magic != MEM_BLOCK_FREED) {
				zend_debug_alloc_output("Freed (magic=0x%0.8X, expected=0x%0.8X)\n", p->magic, MEM_BLOCK_FREED);
			} else {
				zend_debug_alloc_output("Freed\n");
			}
			had_problems = 1;
		} else {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	} else if (ZEND_MM_IS_GUARD_BLOCK(p)) {
		if (!silent) {
			if (p->magic != MEM_BLOCK_FREED) {
				zend_debug_alloc_output("Guard (magic=0x%0.8X, expected=0x%0.8X)\n", p->magic, MEM_BLOCK_FREED);
			} else {
				zend_debug_alloc_output("Guard\n");
			}
			had_problems = 1;
		} else {
			return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
		}
	} else {
		switch (p->magic) {
			case MEM_BLOCK_VALID:
			case MEM_BLOCK_LEAK:
				if (!silent) {
					zend_debug_alloc_output("OK (allocated on %s:%d, %d bytes)\n", p->debug.filename, p->debug.lineno, (int)p->debug.size);
				}
				break; /* ok */
			case MEM_BLOCK_CACHED:
				if (!no_cache_notice) {
					if (!silent) {
						zend_debug_alloc_output("Cached\n");
						had_problems = 1;
					} else {
						return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
					}
				}
			case MEM_BLOCK_FREED:
				if (!silent) {
					zend_debug_alloc_output("Freed (invalid)\n");
					had_problems = 1;
				} else {
					return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
				}
				break;
			case MEM_BLOCK_GUARD:
				if (!silent) {
					zend_debug_alloc_output("Guard (invalid)\n");
					had_problems = 1;
				} else {
					return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
				}
				break;
			default:
				if (!silent) {
					zend_debug_alloc_output("Unknown (magic=0x%0.8X, expected=0x%0.8X)\n", p->magic, MEM_BLOCK_VALID);
					had_problems = 1;
					valid_beginning = 0;
				} else {
					return zend_mm_check_ptr(heap, ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
				}
				break;
		}
	}

#if ZEND_MM_HEAP_PROTECTION
	if (!valid_beginning) {
		if (!silent) {
			zend_debug_alloc_output("%10s\t", "Start:");
			zend_debug_alloc_output("Unknown\n");
			zend_debug_alloc_output("%10s\t", "End:");
			zend_debug_alloc_output("Unknown\n");
		}
	} else {
		char *end_magic = ZEND_MM_END_MAGIC_PTR(p);

		if (p->debug.start_magic == _mem_block_start_magic) {
			if (!silent) {
				zend_debug_alloc_output("%10s\t", "Start:");
				zend_debug_alloc_output("OK\n");
			}
		} else {
			char *overflow_ptr, *magic_ptr=(char *) &_mem_block_start_magic;
			int overflows=0;
			int i;

			if (silent) {
				return _mem_block_check(ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
			}
			had_problems = 1;
			overflow_ptr = (char *) &p->debug.start_magic;
			i = END_MAGIC_SIZE;
			while (--i >= 0) {
				if (overflow_ptr[i]!=magic_ptr[i]) {
					overflows++;
				}
			}
			zend_debug_alloc_output("%10s\t", "Start:");
			zend_debug_alloc_output("Overflown (magic=0x%0.8X instead of 0x%0.8X)\n", p->debug.start_magic, _mem_block_start_magic);
			zend_debug_alloc_output("%10s\t","");
			if (overflows >= END_MAGIC_SIZE) {
				zend_debug_alloc_output("At least %d bytes overflown\n", END_MAGIC_SIZE);
			} else {
				zend_debug_alloc_output("%d byte(s) overflown\n", overflows);
			}
		}
		if (memcmp(end_magic, &_mem_block_end_magic, END_MAGIC_SIZE)==0) {
			if (!silent) {
				zend_debug_alloc_output("%10s\t", "End:");
				zend_debug_alloc_output("OK\n");
			}
		} else {
			char *overflow_ptr, *magic_ptr=(char *) &_mem_block_end_magic;
			int overflows=0;
			int i;

			if (silent) {
				return _mem_block_check(ptr, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
			}
			had_problems = 1;
			overflow_ptr = (char *) end_magic;

			for (i=0; i < END_MAGIC_SIZE; i++) {
				if (overflow_ptr[i]!=magic_ptr[i]) {
					overflows++;
				}
			}

			zend_debug_alloc_output("%10s\t", "End:");
			zend_debug_alloc_output("Overflown (magic=0x%0.8X instead of 0x%0.8X)\n", *end_magic, _mem_block_end_magic);
			zend_debug_alloc_output("%10s\t","");
			if (overflows >= END_MAGIC_SIZE) {
				zend_debug_alloc_output("At least %d bytes overflown\n", END_MAGIC_SIZE);
			} else {
				zend_debug_alloc_output("%d byte(s) overflown\n", overflows);
			}
		}
	}
#endif

	if (!silent) {
		zend_debug_alloc_output("---------------------------------------\n");
	}
	return ((!had_problems) ? 1 : 0);
}

static int zend_mm_check_heap(zend_mm_heap *heap, int silent ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_segment *segment = heap->segments_list;
	zend_mm_block *p, *q;
	int errors = 0;

	if (!segment) {
		return 0;
	}
	p = (zend_mm_block *) ((char *) segment + ZEND_MM_ALIGNED_SEGMENT_SIZE);
	while (1) {
		q = ZEND_MM_NEXT_BLOCK(p);
		if (q <= p ||
		    (char*)q > (char*)segment + segment->size ||
		    p->info._size != q->info._prev) {
			zend_mm_panic("zend_mm_heap corrupted");
		}
		if (!ZEND_MM_IS_FREE_BLOCK(p)) {
			if (p->magic == MEM_BLOCK_VALID || p->magic == MEM_BLOCK_LEAK) {
				if (!zend_mm_check_ptr(heap, ZEND_MM_DATA_OF(p), (silent?2:3) ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC)) {
					errors++;
				}
#if ZEND_MM_CACHE
			} else if (p->magic == MEM_BLOCK_CACHED) {
				/* skip it */
#endif
			} else if (p->magic != MEM_BLOCK_LEAK) {
				zend_mm_panic("zend_mm_heap corrupted");
			}
		}
		if (ZEND_MM_IS_GUARD_BLOCK(q)) {
			segment = segment->next_segment;
			if (!segment) {
				return errors;
			}
			q = (zend_mm_block *) ((char *) segment + ZEND_MM_ALIGNED_SEGMENT_SIZE);
		}
		p = q;
	}
}
#endif
//END OF ZEND_DEBUG

ZEND_API void zend_mm_shutdown(zend_mm_heap *heap, int full_shutdown, int silent TSRMLS_DC)
{
	zend_mm_storage *storage;
	zend_mm_segment *segment;
	zend_mm_segment *prev;
	int internal;

	if (!heap->use_zend_alloc) {  //为启用ZMM
		if (full_shutdown) {
			free(heap);
		}
		return;
	}

	if (heap->reserve) {
#if ZEND_DEBUG
		if (!silent) {
			_zend_mm_free_int(heap, heap->reserve ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC);
		}
#endif
		heap->reserve = NULL;
	}

#if ZEND_MM_CACHE_STAT
	if (full_shutdown) {
		FILE *f;

		f = fopen("zend_mm.log", "w");
		if (f) {
			int i,j;
			size_t size, true_size, min_size, max_size;
			int hit = 0, miss = 0;

			fprintf(f, "\nidx min_size max_size true_size  max_len     hits   misses\n");
			size = 0;
			while (1) {
				true_size = ZEND_MM_TRUE_SIZE(size);
				if (ZEND_MM_SMALL_SIZE(true_size)) {
					min_size = size;
					i = ZEND_MM_BUCKET_INDEX(true_size);
					size++;
					while (1) {
						true_size = ZEND_MM_TRUE_SIZE(size);
						if (ZEND_MM_SMALL_SIZE(true_size)) {
							j = ZEND_MM_BUCKET_INDEX(true_size);
							if (j > i) {
								max_size = size-1;
								break;
							}
						} else {
							max_size = size-1;
							break;
						}
						size++;
					}
					hit += heap->cache_stat[i].hit;
					miss += heap->cache_stat[i].miss;
					fprintf(f, "%2d %8d %8d %9d %8d %8d %8d\n", i, (int)min_size, (int)max_size, ZEND_MM_TRUE_SIZE(max_size), heap->cache_stat[i].max_count, heap->cache_stat[i].hit, heap->cache_stat[i].miss);
				} else {
					break;
				}
			}
			fprintf(f, "                                        %8d %8d\n", hit, miss);
			fprintf(f, "                                        %8d %8d\n", heap->cache_stat[ZEND_MM_NUM_BUCKETS].hit, heap->cache_stat[ZEND_MM_NUM_BUCKETS].miss);
			fclose(f);
		}
	}
#endif

#if ZEND_DEBUG
	if (!silent) {
		zend_mm_check_leaks(heap TSRMLS_CC);
	}
#endif

	internal = heap->internal;
	storage = heap->storage;
	segment = heap->segments_list;
	if (full_shutdown) {
		while (segment) {
			prev = segment;
			segment = segment->next_segment;
			ZEND_MM_STORAGE_FREE(prev);
		}
		heap->segments_list = NULL;
		storage->handlers->dtor(storage);
		if (!internal) {
			free(heap);
		}
	} else {
		if (segment) {
#ifndef ZEND_WIN32
			if (heap->reserve_size) {
				while (segment->next_segment) {
					prev = segment;
					segment = segment->next_segment;
					ZEND_MM_STORAGE_FREE(prev);
				}
				heap->segments_list = segment;
			} else {
#endif
				do {
					prev = segment;
					segment = segment->next_segment;
					ZEND_MM_STORAGE_FREE(prev);
				} while (segment);
				heap->segments_list = NULL;
#ifndef ZEND_WIN32
			}
#endif
		}
		if (heap->compact_size &&
		    heap->real_peak > heap->compact_size) {
			storage->handlers->compact(storage);
		}
		zend_mm_init(heap);
		if (heap->segments_list) {
			heap->real_size = heap->segments_list->size;
			heap->real_peak = heap->segments_list->size;
		} else {
			heap->real_size = 0;
			heap->real_peak = 0;
		}
		heap->size = 0;
		heap->peak = 0;
		if (heap->segments_list) {
			/* mark segment as a free block */
			zend_mm_free_block *b = (zend_mm_free_block*)((char*)heap->segments_list + ZEND_MM_ALIGNED_SEGMENT_SIZE);
			size_t block_size = heap->segments_list->size - ZEND_MM_ALIGNED_SEGMENT_SIZE - ZEND_MM_ALIGNED_HEADER_SIZE;

			ZEND_MM_MARK_FIRST_BLOCK(b);
			ZEND_MM_LAST_BLOCK(ZEND_MM_BLOCK_AT(b, block_size));
			ZEND_MM_BLOCK(b, ZEND_MM_FREE_BLOCK, block_size);
			zend_mm_add_to_free_list(heap, b);
		}
		if (heap->reserve_size) {
			heap->reserve = _zend_mm_alloc_int(heap, heap->reserve_size  ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC);
		}
		heap->overflow = 0;
	}
}

static void zend_mm_safe_error(zend_mm_heap *heap,
	const char *format,
	size_t limit,
#if ZEND_DEBUG
	const char *filename,
	uint lineno,
#endif
	size_t size)
{
	if (heap->reserve) {
		_zend_mm_free_int(heap, heap->reserve ZEND_FILE_LINE_CC ZEND_FILE_LINE_EMPTY_CC);
		heap->reserve = NULL;
	}
	if (heap->overflow == 0) {
		const char *error_filename;
		uint error_lineno;
		TSRMLS_FETCH();
		if (zend_is_compiling(TSRMLS_C)) {
			error_filename = zend_get_compiled_filename(TSRMLS_C);
			error_lineno = zend_get_compiled_lineno(TSRMLS_C);
		} else if (EG(in_execution)) {
			error_filename = EG(active_op_array)?EG(active_op_array)->filename:NULL;
			error_lineno = EG(opline_ptr)?(*EG(opline_ptr))->lineno:0;
		} else {
			error_filename = NULL;
			error_lineno = 0;
		}
		if (!error_filename) {
			error_filename = "Unknown";
		}
		heap->overflow = 1;
		zend_try {
			zend_error_noreturn(E_ERROR,
				format,
				limit,
#if ZEND_DEBUG
				filename,
				lineno,
#endif
				size);
		} zend_catch {
			if (heap->overflow == 2) {
				fprintf(stderr, "\nFatal error: ");
				fprintf(stderr,
					format,
					limit,
#if ZEND_DEBUG
					filename,
					lineno,
#endif
					size);
				fprintf(stderr, " in %s on line %d\n", error_filename, error_lineno);
			}
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
			fflush(stderr);
#endif
		} zend_end_try();
	} else {
		heap->overflow = 2;
	}
	zend_bailout();
}

static zend_mm_free_block *zend_mm_search_large_block(zend_mm_heap *heap, size_t true_size)
{
	zend_mm_free_block *best_fit;
	size_t index = ZEND_MM_LARGE_BUCKET_INDEX(true_size); //最高位1是第几位，返回：下标 = 位-1
	size_t bitmap = heap->large_free_bitmap >> index;	//对应位移到最右边
	zend_mm_free_block *p;

	if (bitmap == 0) {	//所有位都为0，表示已经没有可用内存了
		return NULL;
	}

	if (UNEXPECTED((bitmap & 1) != 0)) {	//对应位有空闲内存
		/* Search for best "large" free block */
		zend_mm_free_block *rst = NULL;
		size_t m;
		size_t best_size = -1;	//无符号的话是最大值

		best_fit = NULL;
		p = heap->large_free_buckets[index];
		//最高位1正好被移去
		for(m = true_size << (ZEND_MM_NUM_BUCKETS - index); ; m <<= 1) {
			/*
			 * 如果p大小正好等于true_size，则说明找到了最合适的节点
			 * 将这个节点所在链表指向的下一个节点返回。
			 * 这个链表是循环链表，当只有p一个节点时，p->next_free_block指向p，返回的是p
			 * 这时用p子树的叶子替换p链接到p->parent，
			 * 这个操作将在_zend_mm_alloc_int中的zend_mm_remove_from_free_list函数进行。
			*/
			if (UNEXPECTED(ZEND_MM_FREE_BLOCK_SIZE(p) == true_size)) {
				return p->next_free_block;
			} else if (ZEND_MM_FREE_BLOCK_SIZE(p) >= true_size &&
			           ZEND_MM_FREE_BLOCK_SIZE(p) < best_size) { //记录下比true_size大又最接近true_size大小的节点，根节点和左右孩子大小没有必然联系，但是左孩子一定小于右孩子
				best_size = ZEND_MM_FREE_BLOCK_SIZE(p);	//最接近true_size的大小
				best_fit = p; //当前最合适的节点
			}
			if ((m & (ZEND_MM_LONG_CONST(1) << (ZEND_MM_NUM_BUCKETS-1))) == 0) {  //m最高位为0
				if (p->child[1]) {
					rst = p->child[1];  //记录下右孩子。rst means: right sub tree
				}
				if (p->child[0]) {
					p = p->child[0];	//最高位为0所以进入左孩子
				} else {
					break;	//没有左孩子退出循环
				}
			} else if (p->child[1]) {  //m最高位为1 & p有右孩子
				p = p->child[1];	//最高位为1所以进入右孩子
			} else { //m最高位为1 & p没有右孩子
				break;
			}
		}
		//程序到达这里说明没有找到和true_size相同大小的节点p
		//rst是最接近true_size的节点，这里不明白，左孩子有路不走走右孩子
		for (p = rst; p; p = p->child[p->child[0] != NULL]) {
			if (UNEXPECTED(ZEND_MM_FREE_BLOCK_SIZE(p) == true_size)) {  //找到大小为size的节点
				return p->next_free_block;
			} else if (ZEND_MM_FREE_BLOCK_SIZE(p) > true_size &&
			           ZEND_MM_FREE_BLOCK_SIZE(p) < best_size) {  //寻找大小最接近的节点
				best_size = ZEND_MM_FREE_BLOCK_SIZE(p);
				best_fit = p;
			}
		}
		//找到大小最接近的节点，返回地址
		if (best_fit) {
			return best_fit->next_free_block;
		}
		//没有找到，找large_free_buckets下一位置
		bitmap = bitmap >> 1;
		if (!bitmap) {	//都没有节点了
			return NULL;
		}
		index++;	//large_free_buckets下标加1
	}
	//到large_free_buckets其他下标位置寻找大小最适合的
	/* Search for smallest "large" free block */
	best_fit = p = heap->large_free_buckets[index + zend_mm_low_bit(bitmap)];  //寻找第一个有节点的位置
	while ((p = p->child[p->child[0] != NULL])) {	//又是左孩子有路不走走右孩子，一定要弄明白为什么
		if (ZEND_MM_FREE_BLOCK_SIZE(p) < ZEND_MM_FREE_BLOCK_SIZE(best_fit)) {
			best_fit = p;
		}
	}
	return best_fit->next_free_block;
}

static void *_zend_mm_alloc_int(zend_mm_heap *heap, size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_free_block *best_fit;
	size_t true_size = ZEND_MM_TRUE_SIZE(size);
	size_t block_size;
	size_t remaining_size;
	size_t segment_size;
	zend_mm_segment *segment;
	int keep_rest = 0;
#ifdef ZEND_SIGNALS
	TSRMLS_FETCH();
#endif

	HANDLE_BLOCK_INTERRUPTIONS();

	if (EXPECTED(ZEND_MM_SMALL_SIZE(true_size))) {	//小块内存
		size_t index = ZEND_MM_BUCKET_INDEX(true_size);	//取得free_bucket下标
		size_t bitmap;

		if (UNEXPECTED(true_size < size)) { //发生溢出
			goto out_of_memory;
		}
		/*
		 * 如果开启了缓存，先从缓存查找合适的空闲块
		*/
#if ZEND_MM_CACHE
		if (EXPECTED(heap->cache[index] != NULL)) {
			/* Get block from cache */
#if ZEND_MM_CACHE_STAT
			heap->cache_stat[index].count--;
			heap->cache_stat[index].hit++;
#endif
			best_fit = heap->cache[index];
			heap->cache[index] = best_fit->prev_free_block; //从链表中拆下第一个节点
			heap->cached -= true_size;
			ZEND_MM_CHECK_MAGIC(best_fit, MEM_BLOCK_CACHED);
			ZEND_MM_SET_DEBUG_INFO(best_fit, size, 1, 0);
			HANDLE_UNBLOCK_INTERRUPTIONS();
			return ZEND_MM_DATA_OF(best_fit);
 		}
#if ZEND_MM_CACHE_STAT
		heap->cache_stat[index].miss++;	//对应下标的缓存信息，未命中缓存次数加1
#endif
#endif
		//缓存编译未开启或未在缓存中找到空闲块，从小块内存中找
		bitmap = heap->free_bitmap >> index;
		if (bitmap) {	//不为0，存在空闲块
			/* Found some "small" free block that can be used */
			index += zend_mm_low_bit(bitmap);	//寻找第一个空闲块位置下标
			best_fit = heap->free_buckets[index*2];
#if ZEND_MM_CACHE_STAT
			heap->cache_stat[ZEND_MM_NUM_BUCKETS].hit++; //cache_stat[ZEND_MM_NUM_BUCKETS]保存free_buckets查找状态信息
#endif
			goto zend_mm_finished_searching_for_block;
		}
	} //ZEND_MM_SMALL_SIZE(true_size)

#if ZEND_MM_CACHE_STAT
	heap->cache_stat[ZEND_MM_NUM_BUCKETS].miss++;	//未在free_buckets查找到，未命中次数+1
#endif
	//找large_free_bucket树。大块的大小是大于等于544字节的，而此时*很可能*是在树中找小于544字节的空闲快
	//这时会定位到下标0-8位置上，这些位置的位图为0。然后寻找最小的大于true_size的块
	//这就是为什么large_free_bucket需要保留0-8无用的位置，而free_bucket利用起了0-3空闲位置
	best_fit = zend_mm_search_large_block(heap, true_size);
	//不能再申请一个heap->block_size大小的块了，才找rest
	//从链表最后一个往前找最接近true_size的块
	if (!best_fit && heap->real_size >= heap->limit - heap->block_size) { 
		zend_mm_free_block *p = heap->rest_buckets[0];
		size_t best_size = -1;  //无符号最大值
		//遍历一遍rest链表找到与true_size相等大小或最接近的块
		while (p != ZEND_MM_REST_BUCKET(heap)) {
			if (UNEXPECTED(ZEND_MM_FREE_BLOCK_SIZE(p) == true_size)) {	//找到相同大小的block
				best_fit = p;
				goto zend_mm_finished_searching_for_block;
			} else if (ZEND_MM_FREE_BLOCK_SIZE(p) > true_size &&
			           ZEND_MM_FREE_BLOCK_SIZE(p) < best_size) {  //best_fit记录下最接近true_size大小的块
				best_size = ZEND_MM_FREE_BLOCK_SIZE(p);
				best_fit = p;
			}
			p = p->prev_free_block;
		}
	}
	//三大内存池都没有找到需要的块，向系统申请一块段
	if (!best_fit) {
		if (true_size > heap->block_size - (ZEND_MM_ALIGNED_SEGMENT_SIZE + ZEND_MM_ALIGNED_HEADER_SIZE)) {
			/* Make sure we add a memory block which is big enough,
			   segment must have header "size" and trailer "guard" block */
			//申请的内存大于默认段大小，以true_size大小分配。因为段最小分配heap->block_size大小
			segment_size = true_size + ZEND_MM_ALIGNED_SEGMENT_SIZE + ZEND_MM_ALIGNED_HEADER_SIZE;
			segment_size = (segment_size + (heap->block_size-1)) & ~(heap->block_size-1);   //按照heap->block_size对齐，segment_size是heap->block_size的倍数
			keep_rest = 1;  //剩下的内存挂到rest
		} else {
			segment_size = heap->block_size;
		}
		//整形溢出或超过limit限制
		if (segment_size < true_size ||
		    heap->real_size + segment_size > heap->limit) {
			/* Memory limit overflow */
#if ZEND_MM_CACHE
			zend_mm_free_cache(heap);
#endif
			HANDLE_UNBLOCK_INTERRUPTIONS();
#if ZEND_DEBUG
			zend_mm_safe_error(heap, "Allowed memory size of %ld bytes exhausted at %s:%d (tried to allocate %lu bytes)", heap->limit, __zend_filename, __zend_lineno, size);
#else
			zend_mm_safe_error(heap, "Allowed memory size of %ld bytes exhausted (tried to allocate %lu bytes)", heap->limit, size);
#endif
		}
		//向系统申请一段内存
		segment = (zend_mm_segment *) ZEND_MM_STORAGE_ALLOC(segment_size);
		//向系统申请内存失败
		if (!segment) {
			/* Storage manager cannot allocate memory */
#if ZEND_MM_CACHE
			zend_mm_free_cache(heap);
#endif
out_of_memory:
			HANDLE_UNBLOCK_INTERRUPTIONS();
#if ZEND_DEBUG
			zend_mm_safe_error(heap, "Out of memory (allocated %ld) at %s:%d (tried to allocate %lu bytes)", heap->real_size, __zend_filename, __zend_lineno, size);
#else
			zend_mm_safe_error(heap, "Out of memory (allocated %ld) (tried to allocate %lu bytes)", heap->real_size, size);
#endif
			return NULL;
		}
		//ZMM占用内存大小
		heap->real_size += segment_size;
		//内存占用峰值
		if (heap->real_size > heap->real_peak) {
			heap->real_peak = heap->real_size;
		}
		//段内存头插法插入到段内存链表
		segment->size = segment_size;
		segment->next_segment = heap->segments_list;
		heap->segments_list = segment;
		//接下来要给段内存标记一下边界，上边界和下边界
		//移到SEGMENT头部下
		best_fit = (zend_mm_free_block *) ((char *) segment + ZEND_MM_ALIGNED_SEGMENT_SIZE);
		ZEND_MM_MARK_FIRST_BLOCK(best_fit);	//第一个block，((best_fit)->info._prev = ZEND_MM_GUARD_BLOCK)

		block_size = segment_size - ZEND_MM_ALIGNED_SEGMENT_SIZE - ZEND_MM_ALIGNED_HEADER_SIZE;

		ZEND_MM_LAST_BLOCK(ZEND_MM_BLOCK_AT(best_fit, block_size));  //(b)->info._size = ZEND_MM_GUARD_BLOCK | ZEND_MM_ALIGNED_HEADER_SIZE;

	} else {
zend_mm_finished_searching_for_block:
		/* remove from free list */
		ZEND_MM_CHECK_MAGIC(best_fit, MEM_BLOCK_FREED);
		ZEND_MM_CHECK_COOKIE(best_fit);
		ZEND_MM_CHECK_BLOCK_LINKAGE(best_fit);
		zend_mm_remove_from_free_list(heap, best_fit);

		block_size = ZEND_MM_FREE_BLOCK_SIZE(best_fit);
	}
	//如果找到的内存块大于true_size并且剩下的内存还能作为一个空闲块，就分成两块
	remaining_size = block_size - true_size;

	if (remaining_size < ZEND_MM_ALIGNED_MIN_HEADER_SIZE) {	//剩下的内存已经不能作为一个空闲块了，全部分配出去
		true_size = block_size;
		ZEND_MM_BLOCK(best_fit, ZEND_MM_USED_BLOCK, true_size);	//修改下best_fit块和下一块.info.prev的大小和标记
	} else {  //剩下的内存还能作为一个空闲块
		zend_mm_free_block *new_free_block;

		/* prepare new free block */
		ZEND_MM_BLOCK(best_fit, ZEND_MM_USED_BLOCK, true_size); //修改下best_fit块和下一块.info.prev的大小和标记
		new_free_block = (zend_mm_free_block *) ZEND_MM_BLOCK_AT(best_fit, true_size); //new_free_block指向下一块开始处
		ZEND_MM_BLOCK(new_free_block, ZEND_MM_FREE_BLOCK, remaining_size);  //修改下new_free_block块和下一块.info.prev的大小和标记

		/* add the new free block to the free list */
		if (EXPECTED(!keep_rest)) {
			zend_mm_add_to_free_list(heap, new_free_block);  //将分离出来的块插入到树或链表中
		} else {
			zend_mm_add_to_rest_list(heap, new_free_block);  //将分离出来的块插入到rest中
		}
	}

	ZEND_MM_SET_DEBUG_INFO(best_fit, size, 1, 1);

	heap->size += true_size;
	if (heap->peak < heap->size) {
		heap->peak = heap->size;  //内存使用最大值
	}

	HANDLE_UNBLOCK_INTERRUPTIONS();

	return ZEND_MM_DATA_OF(best_fit);
}


static void _zend_mm_free_int(zend_mm_heap *heap, void *p ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_block *mm_block;
	zend_mm_block *next_block;
	size_t size;
#ifdef ZEND_SIGNALS
	TSRMLS_FETCH();
#endif
	if (!ZEND_MM_VALID_PTR(p)) {
		return;
	}

	HANDLE_BLOCK_INTERRUPTIONS();

	mm_block = ZEND_MM_HEADER_OF(p);		//指向block信息头部
	size = ZEND_MM_BLOCK_SIZE(mm_block);  	//获取块大小，= mm_block->into._size
	ZEND_MM_CHECK_PROTECTION(mm_block);		

#if ZEND_DEBUG || ZEND_MM_HEAP_PROTECTION
	memset(ZEND_MM_DATA_OF(mm_block), 0x5a, mm_block->debug.size);
#endif

#if ZEND_MM_CACHE
	//如果是小块内存并且cache未达到限制大小，就将这块内存插入到cache，ZEND_MM_CACHE_SIZE = ZEND_MM_NUM_BUCKETS * 4 * 1024，平均每个cache箱子缓存4kb
	if (EXPECTED(ZEND_MM_SMALL_SIZE(size)) && EXPECTED(heap->cached < ZEND_MM_CACHE_SIZE)) {
		size_t index = ZEND_MM_BUCKET_INDEX(size);  //计算箱号 = (size - 头部) / 8
		zend_mm_free_block **cache = &heap->cache[index];  //将会改变第index号箱的指向
		//将mm_block采用头插法插入到链表中，mm_block空闲了prev_free_block和next_free_block都会被利用起来
		((zend_mm_free_block*)mm_block)->prev_free_block = *cache;
		*cache = (zend_mm_free_block*)mm_block;
		heap->cached += size;  //缓存大小加size
		ZEND_MM_SET_MAGIC(mm_block, MEM_BLOCK_CACHED); //不知作用
#if ZEND_MM_CACHE_STAT  //缓存信息
		if (++heap->cache_stat[index].count > heap->cache_stat[index].max_count) {
			heap->cache_stat[index].max_count = heap->cache_stat[index].count;
		}
#endif
		HANDLE_UNBLOCK_INTERRUPTIONS();
		return;		//内存回收完成
	}
#endif

	heap->size -= size;  //已使用的内存减size
	//next_block定位到物理上下一块内存
	next_block = ZEND_MM_BLOCK_AT(mm_block, size);
	//合并物理上前一块和后一块空闲内存，前一块和后一块内存都有可能空闲，所以用if而不是else if
	if (ZEND_MM_IS_FREE_BLOCK(next_block)) { //如果物理上后一块内存空闲
		zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) next_block); //将其从链表中取出
		size += ZEND_MM_FREE_BLOCK_SIZE(next_block);  //合并两块内存大小
	}
	if (ZEND_MM_PREV_BLOCK_IS_FREE(mm_block)) { //如果物理上前一块内存空闲
		mm_block = ZEND_MM_PREV_BLOCK(mm_block);  //mm_block指向前一块内存开始处
		zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) mm_block); //将其从链表中取出
		size += ZEND_MM_FREE_BLOCK_SIZE(mm_block); //合并两块内存大小
	}
	if (ZEND_MM_IS_FIRST_BLOCK(mm_block) &&
	    ZEND_MM_IS_GUARD_BLOCK(ZEND_MM_BLOCK_AT(mm_block, size))) {  //mm_block的头部和底部都有GUARD_BLOCK标记，是一个完整的段内存，释放掉！
		zend_mm_del_segment(heap, (zend_mm_segment *) ((char *)mm_block - ZEND_MM_ALIGNED_SEGMENT_SIZE));
	} else {
		ZEND_MM_BLOCK(mm_block, ZEND_MM_FREE_BLOCK, size);  //将两块内存合并，重新设置本块_size = size|ZEND_MM_FREE_BLOCK，和下一块_prev = size|ZEND_MM_FREE_BLOCK
		zend_mm_add_to_free_list(heap, (zend_mm_free_block *) mm_block);  //将合并后的块重新计算位置加入到链表中
	}
	HANDLE_UNBLOCK_INTERRUPTIONS();
}

static void *_zend_mm_realloc_int(zend_mm_heap *heap, void *p, size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_block *mm_block = ZEND_MM_HEADER_OF(p);
	zend_mm_block *next_block;
	size_t true_size;
	size_t orig_size;
	void *ptr;
#ifdef ZEND_SIGNALS
	TSRMLS_FETCH();
#endif
	if (UNEXPECTED(!p) || !ZEND_MM_VALID_PTR(p)) {
		return _zend_mm_alloc_int(heap, size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
	}

	HANDLE_BLOCK_INTERRUPTIONS();

	mm_block = ZEND_MM_HEADER_OF(p);
	true_size = ZEND_MM_TRUE_SIZE(size);
	orig_size = ZEND_MM_BLOCK_SIZE(mm_block);
	ZEND_MM_CHECK_PROTECTION(mm_block);

	if (UNEXPECTED(true_size < size)) {
		goto out_of_memory;
	}

	if (true_size <= orig_size) {  //缩小内存
		size_t remaining_size = orig_size - true_size;

		if (remaining_size >= ZEND_MM_ALIGNED_MIN_HEADER_SIZE) {  //缩小剩余的内存还能作为一个空闲块
			zend_mm_free_block *new_free_block;

			next_block = ZEND_MM_BLOCK_AT(mm_block, orig_size);
			if (ZEND_MM_IS_FREE_BLOCK(next_block)) { //下一块是空闲块，将缩小后剩下的内存和下一空闲块合并
				remaining_size += ZEND_MM_FREE_BLOCK_SIZE(next_block);
				zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) next_block);
			}

			/* prepare new free block */
			ZEND_MM_BLOCK(mm_block, ZEND_MM_USED_BLOCK, true_size);		//标记缩小块的缩小后的大小
			new_free_block = (zend_mm_free_block *) ZEND_MM_BLOCK_AT(mm_block, true_size);

			ZEND_MM_BLOCK(new_free_block, ZEND_MM_FREE_BLOCK, remaining_size);  //标记合并块的大小

			/* add the new free block to the free list */
			zend_mm_add_to_free_list(heap, new_free_block);  //合并块插入到空闲结构中
			heap->size += (true_size - orig_size);  //使用内存减少
		}
		//缩小剩余的内存不能作为一个空闲块，全都给p
		ZEND_MM_SET_DEBUG_INFO(mm_block, size, 0, 0);
		HANDLE_UNBLOCK_INTERRUPTIONS();
		return p;
	}
	//以下是增大内存的策略
	//如果启用了缓存并且调整后是小块内存。
	//就从缓存中寻找与true_size大小一致的块，将原来数据复制到新块中
	//原来的块插入到缓存中
#if ZEND_MM_CACHE
	if (ZEND_MM_SMALL_SIZE(true_size)) {
		size_t index = ZEND_MM_BUCKET_INDEX(true_size);
		
		if (heap->cache[index] != NULL) {
			zend_mm_free_block *best_fit;
			zend_mm_free_block **cache;

#if ZEND_MM_CACHE_STAT
			heap->cache_stat[index].count--;
			heap->cache_stat[index].hit++;
#endif
			best_fit = heap->cache[index];
			heap->cache[index] = best_fit->prev_free_block;
			ZEND_MM_CHECK_MAGIC(best_fit, MEM_BLOCK_CACHED);
			ZEND_MM_SET_DEBUG_INFO(best_fit, size, 1, 0);
	
			ptr = ZEND_MM_DATA_OF(best_fit);

#if ZEND_DEBUG || ZEND_MM_HEAP_PROTECTION
			memcpy(ptr, p, mm_block->debug.size);
#else
			memcpy(ptr, p, orig_size - ZEND_MM_ALIGNED_HEADER_SIZE);
#endif

			heap->cached -= true_size - orig_size;

			index = ZEND_MM_BUCKET_INDEX(orig_size);
			cache = &heap->cache[index];

			((zend_mm_free_block*)mm_block)->prev_free_block = *cache;
			*cache = (zend_mm_free_block*)mm_block;
			ZEND_MM_SET_MAGIC(mm_block, MEM_BLOCK_CACHED);
#if ZEND_MM_CACHE_STAT
			if (++heap->cache_stat[index].count > heap->cache_stat[index].max_count) {
				heap->cache_stat[index].max_count = heap->cache_stat[index].count;
			}
#endif

			HANDLE_UNBLOCK_INTERRUPTIONS();
			return ptr;
		}
	}
#endif
	//看看下一块有没有在使用
	next_block = ZEND_MM_BLOCK_AT(mm_block, orig_size);
	//下一块内存是空闲的
	if (ZEND_MM_IS_FREE_BLOCK(next_block)) {
		ZEND_MM_CHECK_COOKIE(next_block);
		ZEND_MM_CHECK_BLOCK_LINKAGE(next_block);
		if (orig_size + ZEND_MM_FREE_BLOCK_SIZE(next_block) >= true_size) {  //下一块内存大小足够用
			size_t block_size = orig_size + ZEND_MM_FREE_BLOCK_SIZE(next_block);
			size_t remaining_size = block_size - true_size;

			zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) next_block);

			if (remaining_size < ZEND_MM_ALIGNED_MIN_HEADER_SIZE) {  //缩小剩余的内存不能作为一个空闲块，全都给它
				true_size = block_size;
				ZEND_MM_BLOCK(mm_block, ZEND_MM_USED_BLOCK, true_size);
			} else {  												//缩小剩余的内存还能作为一个空闲块
				zend_mm_free_block *new_free_block;

				/* prepare new free block */
				ZEND_MM_BLOCK(mm_block, ZEND_MM_USED_BLOCK, true_size);
				new_free_block = (zend_mm_free_block *) ZEND_MM_BLOCK_AT(mm_block, true_size);
				ZEND_MM_BLOCK(new_free_block, ZEND_MM_FREE_BLOCK, remaining_size);

				/* add the new free block to the free list */
				if (ZEND_MM_IS_FIRST_BLOCK(mm_block) &&
				    ZEND_MM_IS_GUARD_BLOCK(ZEND_MM_BLOCK_AT(new_free_block, remaining_size))) {  //如果new_free_block和mm_block构成一个段，就先不使用new_free_block，将它放到rest
					zend_mm_add_to_rest_list(heap, new_free_block);
				} else {
					zend_mm_add_to_free_list(heap, new_free_block);
				}
			}
			ZEND_MM_SET_DEBUG_INFO(mm_block, size, 0, 0);
			heap->size = heap->size + true_size - orig_size;
			if (heap->peak < heap->size) {
				heap->peak = heap->size;
			}
			HANDLE_UNBLOCK_INTERRUPTIONS();
			return p;
		//下一块内存大小不够用，看看是不是一个完整的段，如果是，就能调用realloc增加空间
		} else if (ZEND_MM_IS_FIRST_BLOCK(mm_block) &&
				   ZEND_MM_IS_GUARD_BLOCK(ZEND_MM_BLOCK_AT(next_block, ZEND_MM_FREE_BLOCK_SIZE(next_block)))) {
			zend_mm_remove_from_free_list(heap, (zend_mm_free_block *) next_block);
			goto realloc_segment;  //增加段内存
		}
	//下一块内存不是空闲的	
	} else if (ZEND_MM_IS_FIRST_BLOCK(mm_block) && ZEND_MM_IS_GUARD_BLOCK(next_block)) {  //mm_block是否是完整的段
		zend_mm_segment *segment;
		zend_mm_segment *segment_copy;
		size_t segment_size;
		size_t block_size;
		size_t remaining_size;

realloc_segment:
		/* segment size, size of block and size of guard block */
		if (true_size > heap->block_size - (ZEND_MM_ALIGNED_SEGMENT_SIZE + ZEND_MM_ALIGNED_HEADER_SIZE)) {  //这个好像没什么作用，因为总成立？
			segment_size = true_size+ZEND_MM_ALIGNED_SEGMENT_SIZE+ZEND_MM_ALIGNED_HEADER_SIZE;
			segment_size = (segment_size + (heap->block_size-1)) & ~(heap->block_size-1);
		} else {
			segment_size = heap->block_size;
		}

		segment_copy = (zend_mm_segment *) ((char *)mm_block - ZEND_MM_ALIGNED_SEGMENT_SIZE);
		if (segment_size < true_size ||
		    heap->real_size + segment_size - segment_copy->size > heap->limit) {
			if (ZEND_MM_IS_FREE_BLOCK(next_block)) {
				zend_mm_add_to_free_list(heap, (zend_mm_free_block *) next_block);
			}
#if ZEND_MM_CACHE
			zend_mm_free_cache(heap);
#endif
			HANDLE_UNBLOCK_INTERRUPTIONS();
#if ZEND_DEBUG
			zend_mm_safe_error(heap, "Allowed memory size of %ld bytes exhausted at %s:%d (tried to allocate %ld bytes)", heap->limit, __zend_filename, __zend_lineno, size);
#else
			zend_mm_safe_error(heap, "Allowed memory size of %ld bytes exhausted (tried to allocate %ld bytes)", heap->limit, size);
#endif
			return NULL;
		}

		segment = ZEND_MM_STORAGE_REALLOC(segment_copy, segment_size);  //申请新段大小，realloc会帮我们释放原来的段内存
		if (!segment) {
#if ZEND_MM_CACHE
			zend_mm_free_cache(heap);
#endif
out_of_memory:
			HANDLE_UNBLOCK_INTERRUPTIONS();
#if ZEND_DEBUG
			zend_mm_safe_error(heap, "Out of memory (allocated %ld) at %s:%d (tried to allocate %ld bytes)", heap->real_size, __zend_filename, __zend_lineno, size);
#else
			zend_mm_safe_error(heap, "Out of memory (allocated %ld) (tried to allocate %ld bytes)", heap->real_size, size);
#endif
			return NULL;
		}
		heap->real_size += segment_size - segment->size;  //此时segment->size还是原来的size
		if (heap->real_size > heap->real_peak) {
			heap->real_peak = heap->real_size;
		}

		segment->size = segment_size; //增长都的段内存大小

		//如果是在其他地方新开辟的空间
		//这里并没有修改segment->next_segment，是因为新的segment保存了原来的信息
		if (segment != segment_copy) {  
			zend_mm_segment **seg = &heap->segments_list;
			while (*seg != segment_copy) {
				seg = &(*seg)->next_segment;
			}
			*seg = segment;
			mm_block = (zend_mm_block *) ((char *) segment + ZEND_MM_ALIGNED_SEGMENT_SIZE);
			ZEND_MM_MARK_FIRST_BLOCK(mm_block);
		}

		block_size = segment_size - ZEND_MM_ALIGNED_SEGMENT_SIZE - ZEND_MM_ALIGNED_HEADER_SIZE;
		remaining_size = block_size - true_size;

		/* setup guard block */
		ZEND_MM_LAST_BLOCK(ZEND_MM_BLOCK_AT(mm_block, block_size));
		//同样的，如果还能构成一个空闲块，就分离出来
		if (remaining_size < ZEND_MM_ALIGNED_MIN_HEADER_SIZE) {
			true_size = block_size;
			ZEND_MM_BLOCK(mm_block, ZEND_MM_USED_BLOCK, true_size);
		} else {
			zend_mm_free_block *new_free_block;

			/* prepare new free block */
			ZEND_MM_BLOCK(mm_block, ZEND_MM_USED_BLOCK, true_size);
			new_free_block = (zend_mm_free_block *) ZEND_MM_BLOCK_AT(mm_block, true_size);
			ZEND_MM_BLOCK(new_free_block, ZEND_MM_FREE_BLOCK, remaining_size);

			/* add the new free block to the free list */
			zend_mm_add_to_rest_list(heap, new_free_block); //剩下的内存直接插入到rest了
		}

		ZEND_MM_SET_DEBUG_INFO(mm_block, size, 1, 1);

		heap->size = heap->size + true_size - orig_size;
		if (heap->peak < heap->size) {
			heap->peak = heap->size;
		}

		HANDLE_UNBLOCK_INTERRUPTIONS();
		return ZEND_MM_DATA_OF(mm_block);
	}
	//下一块内存不是空闲的
	ptr = _zend_mm_alloc_int(heap, size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);  //申请一个新的块
#if ZEND_DEBUG || ZEND_MM_HEAP_PROTECTION
	memcpy(ptr, p, mm_block->debug.size);
#else
	memcpy(ptr, p, orig_size - ZEND_MM_ALIGNED_HEADER_SIZE);
#endif
	_zend_mm_free_int(heap, p ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);  //原来的块插入到空闲块结构
	HANDLE_UNBLOCK_INTERRUPTIONS();
	return ptr;
}

ZEND_API void *_zend_mm_alloc(zend_mm_heap *heap, size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	return _zend_mm_alloc_int(heap, size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}

ZEND_API void _zend_mm_free(zend_mm_heap *heap, void *p ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	_zend_mm_free_int(heap, p ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}

ZEND_API void *_zend_mm_realloc(zend_mm_heap *heap, void *ptr, size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	return _zend_mm_realloc_int(heap, ptr, size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}

ZEND_API size_t _zend_mm_block_size(zend_mm_heap *heap, void *p ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	zend_mm_block *mm_block;

	if (!ZEND_MM_VALID_PTR(p)) {
		return 0;
	}
	mm_block = ZEND_MM_HEADER_OF(p);
	ZEND_MM_CHECK_PROTECTION(mm_block);
#if ZEND_DEBUG || ZEND_MM_HEAP_PROTECTION
	return mm_block->debug.size;
#else
	return ZEND_MM_BLOCK_SIZE(mm_block);
#endif
}

/**********************/
/* Allocation Manager */
/**********************/

typedef struct _zend_alloc_globals {
	zend_mm_heap *mm_heap;
} zend_alloc_globals;

#ifdef ZTS
static int alloc_globals_id;
# define AG(v) TSRMG(alloc_globals_id, zend_alloc_globals *, v)
#else
# define AG(v) (alloc_globals.v)
static zend_alloc_globals alloc_globals;
#endif

ZEND_API int is_zend_mm(TSRMLS_D)
{
	return AG(mm_heap)->use_zend_alloc;
}

ZEND_API void *_emalloc(size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	TSRMLS_FETCH();

	if (UNEXPECTED(!AG(mm_heap)->use_zend_alloc)) {
		return AG(mm_heap)->_malloc(size);
	}
	return _zend_mm_alloc_int(AG(mm_heap), size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}

ZEND_API void _efree(void *ptr ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	TSRMLS_FETCH();

	if (UNEXPECTED(!AG(mm_heap)->use_zend_alloc)) {
		AG(mm_heap)->_free(ptr);
		return;
	}
	_zend_mm_free_int(AG(mm_heap), ptr ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}

ZEND_API void *_erealloc(void *ptr, size_t size, int allow_failure ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	TSRMLS_FETCH();

	if (UNEXPECTED(!AG(mm_heap)->use_zend_alloc)) {
		return AG(mm_heap)->_realloc(ptr, size);
	}
	return _zend_mm_realloc_int(AG(mm_heap), ptr, size ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}

ZEND_API size_t _zend_mem_block_size(void *ptr TSRMLS_DC ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	if (UNEXPECTED(!AG(mm_heap)->use_zend_alloc)) {
		return 0;
	}
	return _zend_mm_block_size(AG(mm_heap), ptr ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}

#if defined(__GNUC__) && (defined(__native_client__) || defined(i386))

static inline size_t safe_address(size_t nmemb, size_t size, size_t offset)
{
	size_t res = nmemb;
	unsigned long overflow = 0;

	__asm__ ("mull %3\n\taddl %4,%0\n\tadcl $0,%1"
	     : "=&a"(res), "=&d" (overflow)
	     : "%0"(res),
	       "rm"(size),
	       "rm"(offset));
	
	if (UNEXPECTED(overflow)) {
		zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);
		return 0;
	}
	return res;
}

#elif defined(__GNUC__) && defined(__x86_64__)

static inline size_t safe_address(size_t nmemb, size_t size, size_t offset)
{
        size_t res = nmemb;
        unsigned long overflow = 0;

#ifdef __ILP32__ /* x32 */
# define LP_SUFF "l"
#else /* amd64 */
# define LP_SUFF "q"
#endif

        __asm__ ("mul" LP_SUFF  " %3\n\t"
                 "add %4,%0\n\t"
                 "adc $0,%1"
             : "=&a"(res), "=&d" (overflow)
             : "%0"(res),
               "rm"(size),
               "rm"(offset));

#undef LP_SUFF
        if (UNEXPECTED(overflow)) {
                zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);
                return 0;
        }
        return res;
}

#elif defined(__GNUC__) && defined(__arm__)

static inline size_t safe_address(size_t nmemb, size_t size, size_t offset)
{
        size_t res;
        unsigned long overflow;

        __asm__ ("umlal %0,%1,%2,%3"
             : "=r"(res), "=r"(overflow)
             : "r"(nmemb),
               "r"(size),
               "0"(offset),
               "1"(0));

        if (UNEXPECTED(overflow)) {
                zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);
                return 0;
        }
        return res;
}

#elif defined(__GNUC__) && defined(__aarch64__)

static inline size_t safe_address(size_t nmemb, size_t size, size_t offset)
{
        size_t res;
        unsigned long overflow;

        __asm__ ("mul %0,%2,%3\n\tumulh %1,%2,%3\n\tadds %0,%0,%4\n\tadc %1,%1,xzr"
             : "=&r"(res), "=&r"(overflow)
             : "r"(nmemb),
               "r"(size),
               "r"(offset));

        if (UNEXPECTED(overflow)) {
                zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);
                return 0;
        }
        return res;
}

#elif SIZEOF_SIZE_T == 4 && defined(HAVE_ZEND_LONG64)

static inline size_t safe_address(size_t nmemb, size_t size, size_t offset)
{
	zend_ulong64 res = (zend_ulong64)nmemb * (zend_ulong64)size + (zend_ulong64)offset;

	if (UNEXPECTED(res > (zend_ulong64)0xFFFFFFFFL)) {
		zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);
		return 0;
	}
	return (size_t) res;
}

#else

static inline size_t safe_address(size_t nmemb, size_t size, size_t offset)
{
	size_t res = nmemb * size + offset;
	double _d  = (double)nmemb * (double)size + (double)offset;
	double _delta = (double)res - _d;

	if (UNEXPECTED((_d + _delta ) != _d)) {
		zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);
		return 0;
	}
	return res;
}
#endif


ZEND_API void *_safe_emalloc(size_t nmemb, size_t size, size_t offset ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	return emalloc_rel(safe_address(nmemb, size, offset));
}

ZEND_API void *_safe_malloc(size_t nmemb, size_t size, size_t offset)
{
	return pemalloc(safe_address(nmemb, size, offset), 1);
}

ZEND_API void *_safe_erealloc(void *ptr, size_t nmemb, size_t size, size_t offset ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	return erealloc_rel(ptr, safe_address(nmemb, size, offset));
}

ZEND_API void *_safe_realloc(void *ptr, size_t nmemb, size_t size, size_t offset)
{
	return perealloc(ptr, safe_address(nmemb, size, offset), 1);
}


ZEND_API void *_ecalloc(size_t nmemb, size_t size ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	void *p;
#ifdef ZEND_SIGNALS
	TSRMLS_FETCH();
#endif
	HANDLE_BLOCK_INTERRUPTIONS();

	p = _safe_emalloc(nmemb, size, 0 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
	if (UNEXPECTED(p == NULL)) {
		HANDLE_UNBLOCK_INTERRUPTIONS();
		return p;
	}
	memset(p, 0, size * nmemb);
	HANDLE_UNBLOCK_INTERRUPTIONS();
	return p;
}

ZEND_API char *_estrdup(const char *s ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	int length;
	char *p;
#ifdef ZEND_SIGNALS
	TSRMLS_FETCH();
#endif

	HANDLE_BLOCK_INTERRUPTIONS();

	length = strlen(s)+1;
	p = (char *) _emalloc(length ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
	if (UNEXPECTED(p == NULL)) {
		HANDLE_UNBLOCK_INTERRUPTIONS();
		return p;
	}
	memcpy(p, s, length);
	HANDLE_UNBLOCK_INTERRUPTIONS();
	return p;
}

ZEND_API char *_estrndup(const char *s, uint length ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	char *p;
#ifdef ZEND_SIGNALS
	TSRMLS_FETCH();
#endif

	HANDLE_BLOCK_INTERRUPTIONS();

	p = (char *) _emalloc(length+1 ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
	if (UNEXPECTED(p == NULL)) {
		HANDLE_UNBLOCK_INTERRUPTIONS();
		return p;
	}
	memcpy(p, s, length);
	p[length] = 0;
	HANDLE_UNBLOCK_INTERRUPTIONS();
	return p;
}


ZEND_API char *zend_strndup(const char *s, uint length)
{
	char *p;
#ifdef ZEND_SIGNALS
	TSRMLS_FETCH();
#endif

	HANDLE_BLOCK_INTERRUPTIONS();

	p = (char *) malloc(length+1);
	if (UNEXPECTED(p == NULL)) {
		HANDLE_UNBLOCK_INTERRUPTIONS();
		return p;
	}
	if (length) {
		memcpy(p, s, length);
	}
	p[length] = 0;
	HANDLE_UNBLOCK_INTERRUPTIONS();
	return p;
}


ZEND_API int zend_set_memory_limit(size_t memory_limit)
{
	TSRMLS_FETCH();

	AG(mm_heap)->limit = (memory_limit >= AG(mm_heap)->block_size) ? memory_limit : AG(mm_heap)->block_size;

	return SUCCESS;
}

ZEND_API size_t zend_memory_usage(int real_usage TSRMLS_DC)
{
	if (real_usage) {
		return AG(mm_heap)->real_size;
	} else {
		size_t usage = AG(mm_heap)->size;
#if ZEND_MM_CACHE
		usage -= AG(mm_heap)->cached;
#endif
		return usage;
	}
}

ZEND_API size_t zend_memory_peak_usage(int real_usage TSRMLS_DC)
{
	if (real_usage) {
		return AG(mm_heap)->real_peak;
	} else {
		return AG(mm_heap)->peak;
	}
}

ZEND_API void shutdown_memory_manager(int silent, int full_shutdown TSRMLS_DC)
{
	zend_mm_shutdown(AG(mm_heap), full_shutdown, silent TSRMLS_CC);
}

static void alloc_globals_ctor(zend_alloc_globals *alloc_globals TSRMLS_DC)
{
	char *tmp = getenv("USE_ZEND_ALLOC");

	if (tmp && !zend_atoi(tmp, 0)) {  //不使用Zend管理器
		alloc_globals->mm_heap = malloc(sizeof(struct _zend_mm_heap));
		memset(alloc_globals->mm_heap, 0, sizeof(struct _zend_mm_heap));
		alloc_globals->mm_heap->use_zend_alloc = 0;
		alloc_globals->mm_heap->_malloc = malloc;
		alloc_globals->mm_heap->_free = free;
		alloc_globals->mm_heap->_realloc = realloc;
	} else {  //初始化Zend管理器
		alloc_globals->mm_heap = zend_mm_startup();
	}
}

#ifdef ZTS
static void alloc_globals_dtor(zend_alloc_globals *alloc_globals TSRMLS_DC)
{
	shutdown_memory_manager(1, 1 TSRMLS_CC);
}
#endif

ZEND_API void start_memory_manager(TSRMLS_D)
{
#ifdef ZTS
	ts_allocate_id(&alloc_globals_id, sizeof(zend_alloc_globals), (ts_allocate_ctor) alloc_globals_ctor, (ts_allocate_dtor) alloc_globals_dtor);
#else
	alloc_globals_ctor(&alloc_globals);
#endif
}

ZEND_API zend_mm_heap *zend_mm_set_heap(zend_mm_heap *new_heap TSRMLS_DC)
{
	zend_mm_heap *old_heap;

	old_heap = AG(mm_heap);
	AG(mm_heap) = new_heap;
	return old_heap;
}

ZEND_API zend_mm_storage *zend_mm_get_storage(zend_mm_heap *heap)
{
	return heap->storage;
}

ZEND_API void zend_mm_set_custom_handlers(zend_mm_heap *heap,
                                          void* (*_malloc)(size_t),
                                          void  (*_free)(void*),
                                          void* (*_realloc)(void*, size_t))
{
	heap->use_zend_alloc = 0;
	heap->_malloc = _malloc;
	heap->_free = _free;
	heap->_realloc = _realloc;
}

#if ZEND_DEBUG
ZEND_API int _mem_block_check(void *ptr, int silent ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	TSRMLS_FETCH();

	if (!AG(mm_heap)->use_zend_alloc) {
		return 1;
	}
	return zend_mm_check_ptr(AG(mm_heap), ptr, silent ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
}


ZEND_API void _full_mem_check(int silent ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	int errors;
	TSRMLS_FETCH();

	if (!AG(mm_heap)->use_zend_alloc) {
		return;
	}

	zend_debug_alloc_output("------------------------------------------------\n");
	zend_debug_alloc_output("Full Memory Check at %s:%d\n" ZEND_FILE_LINE_RELAY_CC);

	errors = zend_mm_check_heap(AG(mm_heap), silent ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);

	zend_debug_alloc_output("End of full memory check %s:%d (%d errors)\n" ZEND_FILE_LINE_RELAY_CC, errors);
	zend_debug_alloc_output("------------------------------------------------\n");
}
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: t
 * End:
 */
