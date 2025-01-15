import os
import re
from googletrans import Translator

def translate_text(text):
    translator = Translator()
    translation = translator.translate(text, src='zh-cn', dest='en')
    return translation.text

def process_file(file_path, output_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    translated_lines = []
    for line in lines:
        # Check if the line is a comment
        if line.strip().startswith('#'):
            translated_lines.append(line)
        else:
            # Find all Chinese text within quotes and translate them
            translated_line = re.sub(r'(\"|\')(.*?)(\"|\')', lambda match: f"{match.group(1)}{translate_text(match.group(2))}{match.group(3)}", line)
            translated_lines.append(translated_line)

    with open(output_path, 'w', encoding='utf-8') as file:
        file.writelines(translated_lines)

if __name__ == "__main__":
    for root, _, files in os.walk('.'):
        for file in files:
            if file.endswith('.sh') or file.endswith('.md'):  # Process .sh and .md files
                zh_file_path = os.path.join(root, file)
                en_file_path = os.path.join('languages/en', file)

                if not os.path.exists(os.path.dirname(en_file_path)):
                    print(f"Creating directory: {os.path.dirname(en_file_path)}")
                    os.makedirs(os.path.dirname(en_file_path))

                process_file(zh_file_path, en_file_path)