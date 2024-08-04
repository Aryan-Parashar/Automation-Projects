import PyPDF2
import pyttsx3

def pdf_to_audio(pdf_path, audio_path):
    # Initialize PDF reader and text-to-speech engine
    pdf_reader = PyPDF2.PdfReader(pdf_path)
    tts_engine = pyttsx3.init()

    # Set properties for the text-to-speech engine (optional)
    tts_engine.setProperty('rate', 150)  # Speed of speech
    tts_engine.setProperty('volume', 0.9)  # Volume level (0.0 to 1.0)
    
    # Initialize an empty string to store the text from the PDF
    full_text = ""

    # Iterate through all the pages and extract text
    for page_num in range(len(pdf_reader.pages)):
        page = pdf_reader.pages[page_num]
        text = page.extract_text()
        full_text += text

    # Save the extracted text to a file
    with open("extracted_text.txt", "w", encoding="utf-8") as text_file:
        text_file.write(full_text)

    # Convert the extracted text to speech and save it as an audio file
    tts_engine.save_to_file(full_text, audio_path)
    tts_engine.runAndWait()

    print(f"AudioBook saved to {audio_path}")

if __name__ == "__main__":
    # Path to your PDF file
    pdf_path = "sample.pdf"

    # Path where the audiobook will be saved
    audio_path = "audiobook.mp3"

    # Convert the PDF to audiobook
    pdf_to_audio(pdf_path, audio_path)

#Voice Customization Script
#voices = tts_engine.getProperty('voices')
#for index, voice in enumerate(voices):
 #   print(f"Voice {index}: {voice.name}")

# Set a specific voice (e.g., voices[1] for a female voice if available)
#tts_engine.setProperty('voice', voices[1].id)
