class CommentScrapper:
    def __init__(self, base_url, args, ptjsonlib, head_method_allowed):
    self.ptjsonlib = ptjsonlib
    self.args = args
    self.REST_URL = base_url + "/wp-json"
    self.USERS_TABLE = EnumeratedUserTable()
    self.thread_lock = Lock()
    self.vulnerable_endpoints: set = set()

    self.all_comments = []
    self.external_links = []
    self.email_scraper = get_emails_instance(args=self.args)
    self.http_client = HttpClient(self.args, self.ptjsonlib)


    def scrape_external_links(self, response):

        text = str(self.load_prepare_response_json(response))

        # find all HTTP/HTTPS URLs
        urls = re.findall(r'https?://[^\s"\'<>]+', text)

        # get the domain of the base URL
        base_domain = urllib.parse.urlparse(self.BASE_URL).netloc

        # filter out only external links
        external_links = list(set([url for url in urls if urllib.parse.urlparse(url).netloc != base_domain]))
        self.external_links.extend(external_links)
        return list(set(external_links))



    def _scrape_posts(self) -> list:
        """Scrapes and returns all site """
        posts: list = []
        # Get first page of posts
        response = self.http_client.send_request(url=f"{self.REST_URL}/wp/v2/posts/?per_page=100&page=1", method="GET")

        # Check stability
        if response.status_code != 200:
            print_api_is_not_available(status_code=getattr(response, "status_code", None))
            return

        # Scrape mails
        self.email_scraper.parse_emails_from_response(response=response)

        # scrape links
        self.scrape_external_links(response=response)

        # Add to posts
        posts.extend(self.load_prepare_response_json(response))

        def fetch_page(page):
            url = f"{self.REST_URL}/wp/v2/posts/?per_page=100&page={page}"
            try:
                response = self.http_client.send_request(url, method="GET")
                ptprinthelper.ptprint(url, "ADDITIONS", condition=not self.args.json, end="\r", flush=True, colortext=True, indent=4, clear_to_eol=True)
                with self.thread_lock:
                    self.email_scraper.parse_emails_from_response(response=response)
                    self.scrape_external_links(response=response)


                posts: list = self.load_prepare_response_json(response) #response.json() # List
                return posts if response.status_code == 200 else []
            except Exception as e:
                return []

        # Scrape rest of posts in paralell
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for start_page in range(2, 999, 5):
                # Define the current batch of pages
                batch_pages = range(start_page, start_page + 8)

                # Fetch all pages in this batch in parallel
                batch_results = list(executor.map(fetch_page, batch_pages))

                # Flatten results and add to posts
                for page_posts in batch_results:
                    if page_posts:
                        posts.extend(page_posts)

                    # Stop if any page returned no posts
                if any(len(page_posts) == 0 for page_posts in batch_results):
                    break

        # Run Yoast Scanner againsts all posts.
        if "YOAST" in self.args.tests:
            self.yoast_scraper.parse_posts(data=posts)

        return posts