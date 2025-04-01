"""Yoast SEO scrapper"""

from ptlibs import ptprinthelper
import re

class YoastScraper:

    def __init__(self, args):
        self.result = {"publishers": set(), "twitters": set(), "sites": set(), "users": set()}
        self.args = args

    def parse_posts(self, data):
        """Parse posts from wordpress posts endpoint (/wp-json/wp/v2/posts) and retrieve yoast related stuff."""
        for post in data:
            if post.get("yoast_head_json"):
                post = post.get("yoast_head_json")
                self.result["publishers"].add(post.get("article_publisher", ""))

                self.result["twitters"].add(post.get("twitter_site", ""))
                self.result["twitters"].add(post.get("twitter_creator", ""))

                for site in self.find_key_in_json(post, "sameAs"):
                    self.result["sites"].add(site)

            if post.get("yoast_head"):
                names = re.findall(r"[\"']name[\"']:[\"'](\w+)[\"']", post.get("yoast_head", ""))
                for name in names:
                    self.result["users"].add(name)

    def print_result(self):
        """Print results"""

        if all(not v for v in self.result.values()):
            return

        for key in self.result:
            if isinstance(self.result[key], set):
                self.result[key] = {val for val in self.result[key] if val != ""}

        ptprinthelper.ptprint("Yoast interesting information", "TITLE", condition=not self.args.json, flush=True, indent=0, clear_to_eol=True, colortext="TITLE", newline_above=True)

        # If not result
        if all(not v for v in self.result.values()):
            ptprinthelper.ptprint("No information discovered", "OK", condition=not self.args.json, flush=True, indent=4, clear_to_eol=True)
            return

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
                        return value 
                    elif isinstance(value, (dict, list)):
                        result = self.find_key_in_json(value, target_key)
                        if result:
                            return result

            elif isinstance(data, list):
                for item in data:
                    result = self.find_key_in_json(item, target_key)
                    if result:
                        return result

            return []
        except Exception as e:
            return []