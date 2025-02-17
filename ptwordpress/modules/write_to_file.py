def write_to_file(filename, content):
    try:
        with open(filename, 'a') as file:
            file.write(content + '\n')  # Přidá obsah a nový řádek
    except Exception as e:
        print(f"Došlo k chybě při zapisování do souboru: {e}")
