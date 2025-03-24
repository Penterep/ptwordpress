class APIRoutesWalker:
    def __init__(self, args, ptjsonlib, rest_response):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.rest_response = rest_response
        self.rest_url = rest_response.url
        self.routes_and_status_codes = []

    def run(self):
        routes: dict = self.get_routes_to_test(self.rest_response.json().get("routes"))
        for route in routes:
            self.test_route(route)

    def test_route(self):
        pass

    def get_routes_to_test(self, response_json: dict):
        for route, route_data in response_json.items():
            pass

    def parse_routes_into_nodes(self, url: str) -> list:
        rest_url = self.REST_URL
        routes_to_test = []

        json_response = self.get_wp_json_response(url)
        for route in json_response["routes"].keys():
            nodes_to_add = []
            main = self.ptjsonlib.create_node_object(node_type="endpoint", properties={"url": url + route})
            routes_to_test.append({"id": main["key"], "url": url + route})

            nodes_to_add.append(main)
            for endpoint in json_response["routes"][route]["endpoints"]:
                endpoint_method = self.ptjsonlib.create_node_object(parent=main["key"], parent_type="endpoint", node_type="method", properties={"name": endpoint["methods"]})
                nodes_to_add.append(endpoint_method)

                if endpoint.get("args"):
                    for parameter in endpoint["args"].keys():
                        nodes_to_add.append(self.ptjsonlib.create_node_object(parent=endpoint_method["key"], parent_type="method", node_type="parameter", properties={"name": parameter, "type": endpoint["args"][parameter].get("type"), "description": endpoint["args"][parameter].get("description"), "required": endpoint["args"][parameter].get("required")}))

            self.ptjsonlib.add_nodes(nodes_to_add)

        return routes_to_test

    def update_status_code_in_nodes(self):
        if self.use_json:
            for dict_ in self.routes_and_status_codes:
                for node in self.ptjsonlib.json_object["results"]["nodes"]:
                    if node["key"] == dict_["id"]:
                        node["properties"].update({"status_code": dict_["status_code"]})