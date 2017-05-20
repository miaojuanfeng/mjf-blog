// JavaScript Document
jQuery(function($){
	//排列表盘数字
	$(document).find('.digit').each(function(i){
		var deg = (i + 1) * 30, rad = (Math.PI/180)*(deg-90);
		var x = Math.round( Math.cos(rad) * 110 ), y = Math.round( Math.sin(rad) * 110 );
		this.style.cssText='-webkit-transform: translate3d('+x+'px,'+y+'px,0px);-moz-transform: translateX('+x+') translateY('+y+');transform: translate3d('+x+'px,'+y+'px,0)';
	});
	$(".plugin-myclock").children(".clock").css("-webkit-transform","scale("+($(".plugin-myclock").width()/320)+")");
	$(".plugin-myclock").height(($(".plugin-myclock").width()));
});