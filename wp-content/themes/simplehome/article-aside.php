			<article class="article ">
            	<h1><a href="<?php the_permalink(); ?>" title="<?php the_title();?>" alt="<?php the_title();?>" target="_blank"><?php the_title() ?></a></h1>
            	<div class="aside">
                   <?php 
				   		if (is_single() || is_page()) {
							the_content();
						}else{
				   			echo closetags(mb_substr(get_the_content(),0,950));
						}	
				   ?>
                </div>
                <div class="aside-info"><?php //the_time("l");?>
                <?php
					if (is_single() || is_page()) {
						if (get_post_meta($post->ID, 'weather_value', true)!='') {
							$weather = get_weather();
				?>
							<div class="weather-name"><?=($weather[get_post_meta($post->ID, 'weather_value', true)])?></div>
							<div class="weather-box weather-<?=(get_post_meta($post->ID, 'weather_value', true))?>"></div>
                <?php
						}
					}
				?>
				<div class="tag-box">
					<i class="fa fa-map-marker"></i> 
					<?php
						the_tags();
					?>
				</div>	
				<?php if (!is_single() && !is_page()) { ?><div class="readmore"><a href="<?php the_permalink(); ?>" title="<?php the_title();?>" alt="<?php the_title();?>" target="_blank">+ 阅读全文</a></div><?php } ?>
                </div>
            </article>