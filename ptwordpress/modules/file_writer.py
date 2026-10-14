import os


def write_to_file(filename, content):
    try:
        parent_dir = os.path.dirname(os.path.abspath(filename))
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(filename, 'a') as file:
            file.write(content + '\n')
    except Exception as e:
        print(f"Error writing to file: {e}")
