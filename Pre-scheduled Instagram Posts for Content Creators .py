import pandas as pd
import os
import time
from datetime import datetime
from instabot import Bot

# Instagram bot setup
def post_story(image_path, caption):
    bot = Bot()
    bot.login(username='your_instagram_username', password='your_instagram_password')
    bot.upload_story_photo(image_path, caption=caption)

def main():
    df = pd.read_csv('schedule.csv')  # CSV file with image_path, caption, post_time

    for _, row in df.iterrows():
        image_path = row['image_path']
        caption = row['caption']
        post_time = datetime.strptime(row['post_time'], '%Y-%m-%d %H:%M')

        # Ensure the image file exists
        if not os.path.exists(image_path):
            print(f"Image file {image_path} not found. Skipping.")
            continue

        # Wait until the scheduled post time
        now = datetime.now()
        if post_time > now:
            wait_time = (post_time - now).total_seconds()
            print(f"Waiting for {wait_time} seconds...")
            time.sleep(wait_time)

        # Post the story
        post_story(image_path, caption)

if __name__ == "__main__":
    main()
