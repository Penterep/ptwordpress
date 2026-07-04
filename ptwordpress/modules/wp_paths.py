import re


DEFAULT_WP_DIRECTORIES = {
    "content": "wp-content",
    "includes": "wp-includes",
    "json": "wp-json",
    "admin": "wp-admin",
}


def normalize_wp_directory(value: str) -> str:
    """Return a single path segment without surrounding slashes."""
    return (value or "").strip().strip("/") or ""


def get_wp_directories(args) -> dict:
    """Return configured WordPress directory names with default values."""
    return {
        "content": normalize_wp_directory(getattr(args, "wp_content", DEFAULT_WP_DIRECTORIES["content"])),
        "includes": normalize_wp_directory(getattr(args, "wp_includes", DEFAULT_WP_DIRECTORIES["includes"])),
        "json": normalize_wp_directory(getattr(args, "wp_json", DEFAULT_WP_DIRECTORIES["json"])),
        "admin": normalize_wp_directory(getattr(args, "wp_admin", DEFAULT_WP_DIRECTORIES["admin"])),
    }


def wp_directory_path(args, name: str, *parts: str, trailing_slash: bool = False) -> str:
    """Build a URL path using a configured WordPress directory name."""
    directories = get_wp_directories(args)
    path_parts = [directories[name], *[normalize_wp_directory(part) for part in parts if part]]
    path = "/" + "/".join(part for part in path_parts if part)
    if trailing_slash and not path.endswith("/"):
        path += "/"
    return path


def replace_wp_directory_paths(args, value: str) -> str:
    """Replace default WordPress directory path segments in a URL/path string."""
    if value is None:
        return value

    directories = get_wp_directories(args)
    replacements = {
        DEFAULT_WP_DIRECTORIES["content"]: directories["content"],
        DEFAULT_WP_DIRECTORIES["includes"]: directories["includes"],
        "wp-include": directories["includes"],
        DEFAULT_WP_DIRECTORIES["json"]: directories["json"],
        DEFAULT_WP_DIRECTORIES["admin"]: directories["admin"],
    }
    result = value
    for default, replacement in replacements.items():
        if replacement and default != replacement:
            result = re.sub(rf"(?<![\w-]){re.escape(default)}(?![\w-])", replacement, result)
    return result
