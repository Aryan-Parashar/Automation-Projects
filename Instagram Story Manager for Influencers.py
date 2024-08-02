import pandas as pd
import os
import time
from datetime import datetime
from instabot import Bot
from moviepy.editor import VideoFileClip
from PIL import Image, ImageDraw, ImageFont

# Instagram bot setup
def post_story(media_path, caption):
    bot = Bot()
    bot.login(username='your_instagram_username', password='your_instagram_password')
    bot.upload_story_photo(media_path, caption=caption)

def add_background_music(video_path, music_path, output_path):
    video = VideoFileClip(video_path)
    audio = VideoFileClip(music_path).audio
    video = video.set_audio(audio)
    video.write_videofile(output_path, codec="libx264")

def add_sticker_and_caption(image_path, sticker_path, caption, output_path):
    image = Image.open(image_path)
    sticker = Image.open(sticker_path).resize((100, 100))  # Resize sticker as needed

    # Add sticker to image
    image.paste(sticker, (10, 10), sticker)  # Position the sticker

    # Add caption to image
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    draw.text((10, image.height - 60), caption, font=font, fill="white")

    # Add banned message
    banned_message = "Autogram - Developed by Aryan Parashar"
    draw.text((10, image.height - 30), banned_message, font=font, fill="red")

    # Save the edited image
    image.save(output_path)

def main():
    df = pd.read_csv('schedule.csv')  # CSV file with media_path, caption, post_time, media_type

    for _, row in df.iterrows():
        media_type = row['media_type']  # 'image' or 'video'
        media_path = row['media_path']
        caption = row['caption']
        post_time = datetime.strptime(row['post_time'], '%Y-%m-%d %H:%M')

        # Wait until the scheduled post time
        now = datetime.now()
        if post_time > now:
            wait_time = (post_time - now).total_seconds()
            print(f"Waiting for {wait_time} seconds...")
            time.sleep(wait_time)

        if media_type == 'image':
            output_path = 'pictures/stories/temp_story_image.jpg'
            add_sticker_and_caption(media_path, 'stickers/sticker.png', caption, output_path)
            post_story(output_path, caption)
            os.remove(output_path)  # Clean up

        elif media_type == 'video':
            output_path = 'pictures/stories/temp_story_video.mp4'
            music_path = 'music/background_music.mp3'  # Path to background music
            add_background_music(media_path, music_path, output_path)
            post_story(output_path, caption)
            os.remove(output_path)  # Clean up

if __name__ == "__main__":
    main()
