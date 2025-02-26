from ptlibs import ptprinthelper

class YoastScraper:
    """Yoast SEO scrapper"""

    def __init__(self, args):
        self.result = {"publishers": set(), "twitters": set(), "sites": set()}
        self.args = args

    def parse_posts(self, data):
        """Parse posts from wordpress posts endpoint (/wp-json/wp/v2/posts) and retrieve yoast related stuff."""
        for post in data:
            if post.get("yoast_head_json"):
                #print(post)
                post = post.get("yoast_head_json")
                self.result["publishers"].add(post.get("article_publisher", ""))

                self.result["twitters"].add(post.get("twitter_site", ""))
                self.result["twitters"].add(post.get("twitter_creator", ""))

                for site in self.find_key_in_json(post, "sameAs"):
                    self.result["sites"].add(site)

    def print_result(self):
        if all(not v for v in self.result.values()):
            return

        for key in self.result:
            if isinstance(self.result[key], set):  # Pokud je hodnota set
                self.result[key] = {val for val in self.result[key] if val != ""}

        ptprinthelper.ptprint("Yoast interesting metatags:", "TITLE", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True, colortext="TITLE", newline_above=True)
        for key, value in self.result.items():
            if not value:
                continue
            ptprinthelper.ptprint(f"{key.capitalize()}:", "TEXT", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True, colortext="TITLE")
            if key.upper() == "TWITTERS" and value:
                value = ["https://twitter.com/" + val.split("@")[-1] for val in value]

            ptprinthelper.ptprint('\n        '.join(value), "TEXT", condition=not self.args.json, flush=True, indent=8, clear_to_eol=True, colortext="TITLE")

    def find_key_in_json(self, data, target_key) -> list:
        try:
            if isinstance(data, dict):
                for key, value in data.items():
                    if key == target_key:
                        return value  # Nalezený klíč vrátí hodnotu
                    elif isinstance(value, (dict, list)):
                        result = self.find_key_in_json(value, target_key)
                        if result:  # Pokračujeme pouze pokud výsledek není prázdný
                            return result  

            elif isinstance(data, list):
                for item in data:
                    result = self.find_key_in_json(item, target_key)
                    if result:  
                        return result

            return None  # Pokud nic nenajde, vrátí None místo []
        except Exception as e:
            print(f"Chyba: {e}")
            return None