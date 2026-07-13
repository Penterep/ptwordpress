[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## ptwordpress - Wordpress Security Testing Tool

## Installation

```
pipx install ptwordpress
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
ptwordpress -u https://www.example.com
ptwordpress -u https://www.example.com -w ~/mywordlist
ptwordpress -u https://www.example.com -o ./example -sm ./media
ptwordpress -u https://www.example.com -ts VERSION PLUGINS USERAPIU
ptwordpress -u https://www.example.com -ts MEDIA PAGES POSTS -vv
ptwordpress -u https://www.example.com -pw ~/passwords.txt
ptwordpress -u https://www.example.com -wpc content -wpi includes -wpj api -wpa administration
ptwordpress -gp ./plugins.txt
```

## Options
```
-u     --url           <url>           Connect to URL
-rm    --readme                        Enable readme dictionary attacks
-pd    --plugins                       Enable plugins dictionary attacks
-ts    --tests         <tests>         Specify tests
-o     --output        <file>          Save emails, users, logins and media urls to files
-sm    --save-media    <folder>        Save media to folder
-T     --timeout       <seconds>       Set Timeout
-bw    --block-wait    <miliseconds>   Set miliseconds to wait before trying again when blocked
-p     --proxy         <proxy>         Set Proxy
-c     --cookie        <cookie>        Set Cookie
-a     --user-agent    <agent>         Set User-Agent
-d     --delay         <miliseconds>   Set delay before each request
-ar    --author-range  <author-range>  Set custom range for author enumeration (e.g. 1000-1300)
-w     --wordlist      <directory>     Set custom wordlist directory
-wpc   --wp-content    <directory>     Set WordPress content directory (default wp-content)
-wpi   --wp-includes   <directory>     Set WordPress includes directory (default wp-includes)
-wpj   --wp-json       <directory>     Set WordPress REST API directory (default wp-json)
-wpa   --wp-admin      <directory>     Set WordPress admin directory (default wp-admin)
-H     --headers       <header:value>  Set Header(s)
-wpsk  --wpscan-key    <api-key>       Set WPScan API key (https://wpscan.com)
-pw    --password      [wordlist]      Run password attack on enumerated users
-t     --threads       <threads>       Number of threads (default 10)
-r     --redirects                     Follow redirects (default False)
-dl    --download      <directory>     Download all versions of Wordpress
-gp    --get-plugins   <filename>      Retrieve list of all plugins from wordpress.com api (default plugins.txt in wordlist directory)
-C     --cache                         Cache HTTP communication
-v     --version                       Show script version and exit
-vv    --verbose                       Enable verbose output
-h     --help                          Show this help message and exit
-j     --json                          Output in JSON format
```

## Dependencies
```
ptlibs
defusedxml
bs4
lxml
tqdm
```

## License

Copyright (c) 2025 Penterep Security s.r.o.

ptwordpress is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptwordpress is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptwordpress. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!