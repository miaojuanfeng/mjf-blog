<script src="<?php bloginfo('template_url'); ?>/scripts/jquery.js?ver=1.2"></script>
<script src="<?php bloginfo('template_url'); ?>/scripts/jquery.poshytip.min.js?ver=1.2"></script>
<script src="<?php bloginfo('template_url'); ?>/scripts/jquery.nicescroll.min.js?ver=3.1.2"></script>
<script src="<?php bloginfo('template_url'); ?>/scripts/custom.js?ver=1.0"></script>
    <?php
		if (is_single()) {
	?><script>
	//文章页图片自适应
	function responsiveImg() {
		var img_count=(jQuery('.article .content').find('img')).length;
		if (img_count != 0) {
		var maxwidth=jQuery(".article .content").width();
		for (var i=0;i<=img_count-1;i++) {
			var max_width=jQuery('.article .content img:eq('+i+')');
				if (max_width.width() > maxwidth) {
					max_width.addClass('responsive-img');
				}
			}
		}
	}
	jQuery(function(){
		responsiveImg();
		window.onresize = function(){
			responsiveImg();
		}
	});
    </script><?php
		}
	?>
    <script>
    //custom fixed sidebar
	jQuery(function($){
		var topOffset = 50;
		var displayElementId = new Array('hot_tags-2','nav_menu-3','category-list');
		$(window).scroll(function(){
			if ($(this).scrollTop() >= $(".sidebar").height()+topOffset) {
				if ($(".sidebar").css('position')=='absolute') {
					$(".sidebar").children().hide().each(function(){
						_this = this;
						$.each(displayElementId, function(i, val){
							if ($(_this).attr('id')==val)
								$(_this).show();
						});
					});
					$(".sidebar").css('position','fixed');
					//console.log('fixed');
				}
			} else { 
				if ($(".sidebar").css('position')=='fixed') {
					$(".sidebar").css("position",'absolute').children().show();
					//console.log('absolute');
				}
			}
		});
	});
    </script>
    <?php echo stripslashes(get_option('mytheme_analysis'))."\r\n"; ?>
    <?php wp_footer(); ?>
</body>
</html>
    