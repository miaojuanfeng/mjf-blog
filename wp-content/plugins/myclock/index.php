<?php
/*
Plugin Name: 时钟小工具
Plugin URI: http://www.im050.com/
Description: 小工具，会走动的时钟，启用后请到小工具中设置
Version: 1.0
Author: Memory
Author URI: http://www.im050.com/
License: GPL version 2 or later - http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
*/

function load_style() {
	
	//define current time
	date_default_timezone_set('Asia/Shanghai');
	$sec = date('s');
	$min = date('i')+$sec/60;
	$hour = date('H')+$min/60;
	$hour_deg = floor($hour/12*360);
	$min_deg = floor($min/60*360);
	$sec_deg = floor($sec/60*360);
	
	//enqueue style
	wp_enqueue_style('myclock', WP_PLUGIN_URL."/".dirname(plugin_basename(__FILE__)).'/clock.css', array(), 1.0, false);
	wp_enqueue_script( 'plugin-myclock-js', WP_PLUGIN_URL."/".dirname(plugin_basename(__FILE__)).'/clock.js', false, false , true );
	
	//add inline style
	$clock_inline_style = "@keyframes sec_rotate {
	from {transform: rotate(".$sec_deg."deg);} to {transform: rotate(".(360+$sec_deg)."deg);}
	}
	@-webkit-keyframes sec_rotate {
		from {-webkit-transform: rotate(".$sec_deg."deg);} to {-webkit-transform: rotate(".(360+$sec_deg)."deg);}
	}
	@-moz-keyframes sec_rotate {
		from {-moz-transform: rotate(".$sec_deg."deg);} to {-moz-transform: rotate(".(360+$sec_deg)."deg);}
	}
	@-o-keyframes sec_rotate {
		from {-o-transform: rotate(".$sec_deg."deg);} to {-o-transform: rotate(".(360+$sec_deg)."deg);}
	}
	@keyframes min_rotate {
		from {transform: rotate(".$min_deg."deg);} to {transform: rotate(".(360+$min_deg)."deg);}
	}
	@-webkit-keyframes min_rotate {
		from {-webkit-transform: rotate(".$min_deg."deg);} to {-webkit-transform: rotate(".(360+$min_deg)."deg);}
	}
	@-moz-keyframes min_rotate {
		from {-moz-transform: rotate(".$min_deg."deg);} to {-moz-transform: rotate(".(360+$min_deg)."deg);}
	}
	@-o-keyframes min_rotate {
		from {-o-transform: rotate(".$min_deg."deg);} to {-o-transform: rotate(".(360+$min_deg)."deg);}
	}
	@keyframes hour_rotate {
		from {transform: rotate(".$hour_deg."deg);} to {transform: rotate(".(360+$hour_deg)."deg);}
	}
	@-webkit-keyframes hour_rotate {
		from {-webkit-transform: rotate(".$hour_deg."deg);} to {-webkit-transform: rotate(".(360+$hour_deg)."deg);}
	}
	@-moz-keyframes hour_rotate {
		from {-moz-transform: rotate(".$hour_deg."deg);} to {-moz-transform: rotate(".(360+$hour_deg)."deg);}
	}
	@-o-keyframes hour_rotate {
		from {-o-transform: rotate(".$hour_deg."deg);} to {-o-transform: rotate(".(360+$hour_deg)."deg);}
	};";
    wp_add_inline_style( 'myclock', $clock_inline_style );
}
add_action( 'wp_enqueue_scripts', 'load_style' );

//register widget
include(dirname(__FILE__).'/clock.widget.php');
add_action('widgets_init', create_function('', 'return register_widget("myClock");'));
?>