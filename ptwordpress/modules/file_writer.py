def write_to_file(filename, content):
    try:
        with open(filename, 'a') as file:
            file.write(content + '\n')
    except Exception as e:
        print(f"Error writing to file: {e}")
