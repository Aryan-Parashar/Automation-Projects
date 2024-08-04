import requests

API_KEY = 'getimg.ai API Key'

def generate_image(prompt, output_path):
    url = "https://api.getimg.ai/v1/stable-diffusion/text-to-image"

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "text": prompt,
        "steps": 50,            # Number of diffusion steps (higher values can improve quality)
        "width": 512,           # Width of the generated image
        "height": 512,          # Height of the generated image
        "cfg_scale": 7.5,       # Classifier-free guidance scale (controls adherence to prompt)
        "samples": 1            # Number of images to generate
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()  # Raise an error for bad HTTP responses

        # Parse the JSON response to get image URLs
        image_data = response.json()
        image_url = image_data.get("images", [{}])[0].get("url", None)

        if not image_url:
            print("Failed to retrieve image URL from response.")
            return False

        # Download and save the image
        image_response = requests.get(image_url)
        image_response.raise_for_status()

        with open(output_path, 'wb') as f:
            f.write(image_response.content)

        print(f"Image successfully generated and saved to {output_path}")
        return True

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return False

if __name__ == "__main__":
    prompt = "A Funny Fat Cat."
    output_path = "generated_image.png"

    # Generate the image
    generate_image(prompt, output_path)
