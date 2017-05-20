<?php
/**
*
* @widget
* 时钟
* author: @memory
*
*/
class myClock extends WP_Widget {

	//construct
	function myClock() {
		parent::WP_Widget('my_clock', '我的时钟', array('description' =>  '我的时钟(SimpleHome)') );  
	}
	
	//display format
	function widget($args, $instance) {     
		extract( $args );
	?>

		<div class="plugin-myclock">
			<div class="clock" id="my_clock">
                <div class="pivot"></div>
                <div class="hour-hand clock-hand"></div>
                <div class="minute-hand clock-hand"></div>
                <div class="second-hand clock-hand"></div>
                <span class="digit">1</span>
                <span class="digit">2</span>
                <span class="digit">3</span>
                <span class="digit">4</span>
                <span class="digit">5</span>
                <span class="digit">6</span>
                <span class="digit">7</span>
                <span class="digit">8</span>
                <span class="digit">9</span>
                <span class="digit">10</span>
                <span class="digit">11</span>
                <span class="digit">12</span>
            </div>
        </div>
		<?php
    }
	
	//save options
	function update($new_instance, $old_instance) {             
		return $new_instance;
	}
	
	//widget options
	function form($instance) {              
		$title = isset($instance['title']) ? esc_attr($instance['title']) : '时钟';
		?>
		<p><label for="<?php echo $this->get_field_id('title'); ?>">标题：<input class="widefat" id="<?php echo $this->get_field_id('title'); ?>" name="<?php echo $this->get_field_name('title'); ?>" type="text" value="<?php echo $title; ?>" /></label></p>
		<?php 
    }
}
?>