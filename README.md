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
```

## Options
```
-u     --url           <url>           Connect to URL
-rm    --readme                        Enable readme dictionary attacks
-pd    --plugins                       Enable plugins dictionary attacks
-o     --output        <file>          Save emails, users, logins and media urls to files
-sm    --save-media    <folder>        Save media to folder
-T     --timeout       <seconds>       Set Timeout
-p     --proxy         <proxy>         Set Proxy
-c     --cookie        <cookie>        Set Cookie
-a     --user-agent    <agent>         Set User-Agent
-d     --delay         <miliseconds>   Set delay before each request
-ar    --author-range  <author-range>  Set custom range for author enumeration (e.g. 1000-1300)
-w     --wordlist      <directory>     Set custom wordlist directory
-H     --headers       <header:value>  Set Header(s)
-wpsk  --wpscan-key    <api-key>       Set WPScan API key (https://wpscan.com)
-t     --threads       <threads>       Number of threads (default 10)
-r     --redirects                     Follow redirects (default False)
-dl    --download      <directory>     Download all versions of Wordpress
-gp    --get-plugins                   Retrieve list of all plugins from wordpress.com api (save in wordlist directory)
-C     --cache                         Cache HTTP communication
-v     --version                       Show script version and exit
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