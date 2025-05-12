copied from [Break intro cyber security](https://jhalon.github.io/breaking-into-cyber-security/)

# Things to recap and learn

- Networking
    - IP Addresses: Understand both IPv4 and IPv6 and how they are used.
    - Ports: Understand common ports and the services they correspond to (HTTP/HTTPS, SSH, etc.).
    - CIDR Notation: Understand how to define and calculate network ranges using CIDR.
    - TCP/IP Stack: Understand the layers in the TCP/IP model as well as how and what type of data flows through each layer.
    - Subnetting: Understand how to divide networks into smaller subnets and calculate network masks.
    - DNS: Understand how the Domain Name System works by knowing how domain names are resolved into IP addresses and vice versa.
    - Routing, Switching, and Firewalls: Understand how routers and switches work to direct network traffic and how firewalls (and VLANS) are used to isolate traffic.

- Encryption and Cryptography:
    - Basic Cryptography: Understand the difference between symmetric vs. asymmetric encryption, know what hashing is, and what Diffie-Hellman is.
    - SSL/TLS: Understand how SSL/TLS work and how they are used to encrypt network traffic.
    - Common Algorithms: Become familiar with common encryption algorithms like AES, RC4, RSA, and hashing algorithms such as SHA1, and MD5.


- Operating System Knowledge:
    - Windows Internals: Understand the basics like file systems, user accounts, the registry, event logs, kernel, userland, and basics around process and memory management.
    - Linux Internals: Become familiar with the file system structure, user permissions, processes, and simple things like daemons.
    - Command Line Proficiency: Become familiar with system commands and learn how to use the Windows Command Prompt and Linux Bash Terminal.


- Web Applications:
    - Basics: Understand HTTP/HTTPS, request-response cycles, REST APIs, and common web architectures.
    - Session Management: Understand how sessions are managed, including cookies, tokens, and secure session handling.
    - Backend Basics: Understand a common web application stack, and how data is handled on the backend of the application via technologies like SQL.


- Active Directory:
    - Directory Structure: Understand the organizational structure of Active Directory (AD), such as domains, forests, and organizational units (OUs).
    - User and Group Management: Understand how users accounts and groups are managed, and understand the basic permissions within AD.
    - Authentication Protocols: Become familiar with and understand how NTLM and Kerberos works, and how they are used to authenticate users.


- Basic Malware and Threats:
    - Malware Types: Understand the different types of malware such as viruses, worms, ransomware, rootkits, and how they can infect systems.
    - Threat Vectors: Understand the different threat vectors and attack types such as phishing, social engineering, impersonation, etc.


- Common Attacks and Vulnerabilities:
    - Web Vulnerabilities: Become familiar with the OWASP Top 10, and common attacks like Cross Site Scripting (XSS), SQL Injection, Cross Site Request Forgery, Denial of Service, etc.
    - Operating System Attacks & Vulns: Understand basic system exploits and attacks such as Buffer Overflows, Memory Injection, Race Conditions, Privilege Escalation, etc.


# Web Hacking

As a penetration tester, you’ll be testing the security of a wide range of online platforms, such as banking applications, ecommerce websites, cloud hosting services, and more. To do this effectively you’ll need to go beyond the basic web application vulnerabilities like Cross-Site Scripting (XSS), SQL Injection (SQLi), and Cross-Site Request Forgery (CSRF). You’ll also need to be familiar with more advanced vulnerabilities, including XML External Entity (XXE) attacks, XML and JSON injection, LDAP injection, and blind injections. Other important issues include code and template injection, subdomain takeovers, open redirects, Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and Remote File Inclusion (RFI) to name a few.

Additionally, understanding key protocols and how they’re implemented such as [OAuth](https://oauth.net/2/), and [SSO](https://en.wikipedia.org/wiki/Single_sign-on) will be crucial. Familiarity with the security challenges specific to certain platforms, like GitHub, Jenkins and Elasticsearch, is also vital for identifying potential vulnerabilities.

To add on to that, it also helps understanding the language the web app is built on, since a ton of web assessments are at times paired with code reviews. Knowing languages such as Java, JavaScript, Scala, PHP or ASP.NET will really help spot those hidden gems that might not come up in a [black box](https://en.wikipedia.org/wiki/Black-box_testing) assessment.

### Resources

-   [Apps for Testing & Practice](https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project#tab=Main)
-   [Awesome CI/CD Attacks](https://github.com/TupleType/awesome-cicd-attacks)
-   [Awesome Web Hacking](https://github.com/infoslack/awesome-web-hacking)
-   [Awesome Web Security](https://github.com/qazbnm456/awesome-web-security)
-   [Bug Bounty Bootcamp: The Guide to Finding and Reporting Web Vulnerabilities](https://nostarch.com/bug-bounty-bootcamp)
-   [Bug Bounty Reference](https://github.com/ngalongc/bug-bounty-reference)
-   [Detectify Security Blog](https://labs.detectify.com/)
-   [Hacker 101](https://www.hacker101.com/)
-   [HackerOne Hacktivity](https://hackerone.com/hacktivity?sort_type=latest_disclosable_activity_at&filter=type%3Apublic&page=1)
-   [Hacking APIs: Breaking Web Application Programming Interfaces](https://nostarch.com/hacking-apis)
-   [HackTheBox Academy: Bug Bounty Hunter](https://academy.hackthebox.com/path/preview/bug-bounty-hunterr)
-   [HackTheBox Academy: Senior Web Penetration Tester](https://academy.hackthebox.com/path/preview/senior-web-penetration-tester)
-   [InfoSec Write-Ups: Bug Bounty](https://infosecwriteups.com/tagged/bug-bounty)
-   [James Kettle / albinowax Research](https://skeletonscribe.net/)
-   [LiveOverflow: Web Hacking Video Series](https://www.youtube.com/watch?v=jmgsgjPn1vs&list=PLhixgUqwRTjx2BmNF5-GddyqZcizwLLGP)
-   [OWASP Top 10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)
-   [OWASP WAPT Testing Guide](https://www.owasp.org/index.php/Web_Application_Penetration_Testing)
-   [PentesterLab Bootcamp](https://pentesterlab.com/bootcamp)
-   [PentesterLand: Bug Bounty Writeups](https://pentester.land/writeups/)
-   [PortSwigger Research](https://portswigger.net/research)
-   [PortSwigger: WebSecurity Academy](https://portswigger.net/web-security)
-   [Real-World Bug Hunting: A Field Guide to Web Hacking](https://nostarch.com/bughunting)
-   [SANS 2016 Holiday Hack Challenge](https://jhalon.github.io/sans-2016-holiday-hack-challenge/)
-   [Source Incite Blog](https://srcincite.io/blog/)
-   [Stanford CS253: Web Security](https://web.stanford.edu/class/cs253/)
-   [TryHackMe: DevSecOps](https://tryhackme.com/r/path/outline/devsecops)
-   [TryHackMe: Web Fundamental](https://tryhackme.com/r/path/outline/web)
-   [TryHackMe: Web Application Pentesting](https://tryhackme.com/r/path/outline/webapppentesting)
-   [The Tangled Web: A Guide to Securing Modern Web Applications](https://www.amazon.com/Tangled-Web-Securing-Modern-Applications/dp/1593273886)
-   [The Web Application Hacker’s Handbook: Finding and Exploiting Security Flaws](https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470)
-   [Youtube: PwnFunction](https://www.youtube.com/@PwnFunction/videos)
-   [Youtube: STOK](https://www.youtube.com/@STOKfredrik/videos)


# Network Hacking

As a pentester you will be tasked with trying to assess the risk of a potential security breach, which isn’t just about gaining high-level access, like becoming a Domain Admin, but about identifying and evaluating what kind of proprietary data is unprotected and out in the open.

During your assessment, you’ll look for areas where sensitive information could be compromised. Are user accounts and credentials stored securely, or are they easily accessible? Can customer data such as credit card information be found with minimal effort? How well-trained are employees in spotting common security threats like phishing? Are security technologies properly configured and functioning? And more!

To be able to carry out a Network Pentest you need a deep understanding of how networks operate. You should be familiar with networking technologies and communication protocols like TCP/IP, LDAP, SNMP, SMB, and VoIP to name a few. You’ll also need to understand enterprise technologies like Active Directory and how they manage user access and permissions since identifying misconfigurations is a critical part of network pentesting, like poorly configured access control lists (ACLs), and open file shares that could expose sensitive data. You need to also understand how Windows and Linux internals function, and how you can utilize them to further compromise other users and host systems.


### Resources

-   [Active Directory Kill Chain Attack & Defense](https://github.com/infosecn1nja/AD-Attack-Defense)
-   [Active Directory Resources (r/activedirectory)](https://www.reddit.com/r/activedirectory/wiki/ad-resources/)
-   [AD Security](https://adsecurity.org/)
-   [Adversarial Tactics, Techniques & Common Knowledge](https://attack.mitre.org/wiki/Main_Page)
-   [Awesome Pentest](https://github.com/enaqx/awesome-pentest)
-   [Awesome Red Teaming](https://github.com/0xMrNiko/Awesome-Red-Teaming)
-   [Bad Sector Labs: Last Week In Security](https://blog.badsectorlabs.com/)
-   [HackTheBox Academy: Active Directory Enumeration](https://academy.hackthebox.com/path/preview/active-directory-enumeration)
-   [HackTheBox Academy: Active Directory Penetration Tester](https://academy.hackthebox.com/path/preview/active-directory-penetration-tester)
-   [HackTricks: Pentesting Networks](https://book.hacktricks.wiki/en/index.html)
-   [harmj0y Blogs](https://blog.harmj0y.net/blog/)
-   [Hausec: Domain Penetration Testing Series](https://hausec.com/domain-penetration-testing/)
-   [Infrastructure Pentest Series](https://bitvijays.github.io/index.html)
-   [IppSec’s Videos](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)
-   [Metasploitable](https://information.rapid7.com/download-metasploitable-2017.html)
-   [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)
-   [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/)
-   [Pen Test Partners Blog](https://www.pentestpartners.com/security-blog/)
-   [Penetration Testing Lab](https://pentestlab.blog/)
-   [Pentestit Lab Writeups](https://jhalon.github.io/categories.html)
-   [Red Team Notes](https://www.ired.team/)
-   [Red Teaming Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit)
-   [SANS Penetration Testing Blog](https://www.sans.org/blog/?focus-area=offensive-operations)
-   [SpecterOps: BloodHound Blogs](https://posts.specterops.io/bloodhound/home)
-   [SpecterOps: Blog](https://specterops.io/blog/)
-   [SpecterOps YouTube Videos](https://www.youtube.com/@specterops/videos)
-   [The Hacker Playbook 3: Practical Guide To Penetration Testing](https://www.amazon.com/Hacker-Playbook-Practical-Penetration-Testing-ebook/dp/B07CSPFYZ2)
-   [TryHackMe: Hacking Active Directory](https://tryhackme.com/module/hacking-active-directory)
-   [TryHackMe: Red Teaming](https://tryhackme.com/r/path/outline/redteaming)
-   [Windows APIs](https://docs.microsoft.com/en-us/windows/desktop/apiindex/windows-api-list)
-   [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
-   [ZeroSec: Paving the Way to DA](https://blog.zsec.uk/paving-2-da-wholeset/)
-   Google… Just too much to list!


# Code Review
As a pentester you will probably be reviewing a lot of applications built using C, C++, Java, JavaScript, .NET, Ruby, PHP, Python, and even Go. To be able to thoroughly review the application and find vulnerabilities or security issues you need to have a decent understanding of the underlying language and the issues that might arise.

Do note that some vulnerabilities are more prevalent in only certain languages. For example, buffer overflow are more prevalent in lower-level languages like C and C++, where memory management is done manually. In contrast, languages like Python and .NET are higher-level languages and generally handle memory management automatically via a garbage collector, making such issues less likely. On the other hand, vulnerabilities like deserialization are often found in languages like Python, Java, and .NET, where object data is commonly serialized and deserialized, but are less common in C and C++.

So, all in all, it’s a really good idea to learn a programming language as it will immensely help in your career toward becoming a pentester. Not only will it help you understand how specific vulnerabilities arise in source code, but it will also enable you to write scripts and build exploits that can be used during penetration tests. Whether you’re developing a Proof of Concept (PoC) to demonstrate a vulnerability or quickly creating a fuzzer to test an application, programming knowledge is a powerful tool in your pentester toolkit.

### Resources

-   [24 Deadly Sins of Software Security: Programming Flaws and How to Fix Them](https://www.amazon.com/Deadly-Sins-Software-Security-Programming/dp/0071626751)
-   [Awesome AppSec](https://github.com/paragonie/awesome-appsec)
-   [Awesome Code Review](https://github.com/joho/awesome-code-review)
-   [Awesome Static Analysis](https://github.com/mre/awesome-static-analysis)
-   [Codecademy](https://www.codecademy.com/)
-   [Designing Secure Software](https://nostarch.com/designing-secure-software)
-   [GitLab Security Secure Coding Training](https://handbook.gitlab.com/handbook/security/secure-coding-training/)
-   [Kontar AppSec: Front-End Top 5](https://application.security/free/kontra-front-end-top-5)
-   [Kontar AppSec: OWASP Top 10 API](https://application.security/free/owasp-top-10-API)
-   [Kontar AppSec: OWASP Top 10](https://application.security/free/owasp-top-10)
-   [Open Security: Secure Code Review Guide](https://opensecuritytraining.info/SecureCodeReview.html)
-   [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf)
-   [OWASP Code Review Project](https://www.owasp.org/index.php/Category:OWASP_Code_Review_Project)
-   [OWASP WebGoat](https://github.com/WebGoat/WebGoat)
-   [Secure Coding Dojo](https://owasp.org/SecureCodingDojo/codereview101/)
-   [Static Code Analysis Tools](https://github.com/codefactor-io/awesome-static-analysis)
-   [Synk: Developer Security Training](https://learn.snyk.io/)
-   [Snyk Vulnerability Database](https://security.snyk.io/)
-   [The Art of Software Security Assessment: Identifying and Preventing Software Vulnerabilities](https://www.amazon.com/Art-Software-Security-Assessment-Vulnerabilities/dp/0321444426)
-   [Vulnerabilities 1001: C-Family Software Implementation Vulnerabilities](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Vulns1001_C-family+2023_v1/about)
-   [Vulnerabilities 1002: C-Family Software Implementation Vulnerabilities](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Vulns1002_C-family+2023_v1/about)
-   [CodeQL Zero to Hero Part 1: The Fundamentals of Static Analysis for Vulnerability Research](https://github.blog/2023-03-31-codeql-zero-to-hero-part-1-the-fundamentals-of-static-analysis-for-vulnerability-research/)
-   Reading the Languages Docs
-   Google… like seriously guys!

# Mobile Hacking

As a pentester, if you’re going to be doing Mobile Security then you’ll need to understand ARM Architecture as that’s what you’ll be seeing a lot of when reverse engineering apps and the core OS. For Android it’s best to learn and understand Java and the Android Runtime, but for iOS you’ll need to learn Swift and Objective-C.

Your daily tasks could include reverse engineering mobile apps, reviewing app source code, conducting mobile web application pentests, or even analyzing and securing the core mobile OS. Additionally, mobile security testing often extends to other parts of the phone, such as Bluetooth, Wi-Fi, SMS/MMS protocols, and more, all of which have their own unique attack vectors.

-   [Android Hacker’s Handbook](https://www.amazon.com/Android-Hackers-Handbook-Joshua-Drake/dp/111860864X/ref=dp_rm_img_1)
-   [Android Hacking 101](https://github.com/Devang-Solanki/android-hacking-101)
-   [Android Security Internals: An In-Depth Guide to Android’s Security Architecture](https://www.amazon.com/Android-Security-Internals-Depth-Architecture/dp/1593275811)
-   [Android App Reverse Engineering 101](https://www.ragingrock.com/AndroidAppRE/)
-   [Awesome Mobile Security](https://github.com/vaib25vicky/awesome-mobile-security)
-   [Azeria Labs - ARM Tutorials](https://azeria-labs.com/)
-   [BugCrowd: Mobile Hacking Resource Kit](https://www.bugcrowd.com/wp-content/uploads/2023/12/mobile-hacking-resource-kit.pdf)
-   [Corellium: Hunting for Vulnerabilities in iOS Apps](https://www.corellium.com/hunting-ios-vulnerabilities)
-   [Corellium: Mobile Security Training](https://www.corellium.com/training)
-   [Frida](https://frida.re/docs/home/)
-   [Google: Android App Hacking Workshop](https://bughunters.google.com/learn/presentations/5783688075542528/android-app-hacking-workshop)
-   [Hacker101: Mobile Hacking Crash Course](https://www.hacker101.com/playlists/mobile_hacking.html)
-   [HackTheBox: Intro To Mobile Pentesting](https://www.hackthebox.com/blog/intro-to-mobile-pentesting)
-   [iOS Application Security: The Definitive Guide for Hackers and Developers](https://www.amazon.com/iOS-Application-Security-Definitive-Developers/dp/159327601X)
-   [iOS Hacker’s Handbook](https://www.amazon.com/iOS-Hackers-Handbook-Charlie-Miller/dp/1118204123/ref=pd_lpo_sbs_14_t_2/140-2741177-2826762?_encoding=UTF8&psc=1&refRID=PZKSM7AHR73QPKTT4E31)
-   [iOS Hacking Resources](https://github.com/Siguza/ios-resources)
-   [iPhone Development Wiki](https://iphone-dev.com/)
-   [Mobile Hacking Labs](https://www.mobilehackinglab.com/free-mobile-hacking-labs)
-   [OWASP Mobile Application Security Testing Guide](https://mas.owasp.org/MASTG/)
-   [Reverse Engineering iOS Apps - iOS 11 Edition (Part 1)](https://ivrodriguez.com/reverse-engineer-ios-apps-ios-11-edition-part1/)
-   [The Mobile Application Hacker’s Handbook](https://www.amazon.com/Mobile-Application-Hackers-Handbook/dp/1118958500)
-   Google.


# Cloud Hacking

You hear it pretty much every day, another data breach, all thanks to a [misconfigured S3 Bucket](https://businessinsights.bitdefender.com/worst-amazon-breaches)! With the rapid adoption of cloud services, you’d think security would have kept pace, but unfortunately that’s not always the case.

Cloud platforms like AWS, Azure, and Google Cloud have become incredibly popular, and many companies are migrating or building new infrastructure “in the cloud” because it’s cost-effective and scalable. But just because something is easy to implement doesn’t mean it’s easy to secure.

Unfortunately, many developers, engineers, and even security professionals don’t fully understand the intricacies of cloud security, especially when it comes to configuring services correctly. Securing cloud environments is complex, and if you don’t take the time to properly configure your environment from the start, a lot can go wrong.

For example, a simple [SSRF](https://www.owasp.org/index.php/Server_Side_Request_Forgery) in a web app can lead to the compromise of the underlying cloud infrastructure. At the same time, misconfigured permissions or poorly managed Identity and Access Management (IAM) roles in something like AWS can allow attackers to gain unauthorized access to sensitive services, like cloud storage buckets, manipulate data, or even spin up new compute instances.

As a pentester, if you’re focusing on cloud security, you’ll need a deep understanding of the cloud provider’s infrastructure like AWS, Azure, or GCP. You’ll use this knowledge to assess configurations, such as ensuring user and group roles are appropriately assigned, verifying that storage buckets are secured, checking network security rules, and confirming that secure protocols and encryption practices are implemented throughout the environment.

### Resources
-   [AAD Internals](https://aadinternals.com/)
-   [Awesome AWS Security](https://github.com/jassics/awesome-aws-security)
-   [Awesome Azure Penetration Testing](https://github.com/Kyuu-Ji/Awesome-Azure-Pentest)
-   [AWS Certified Security - Specialty](https://aws.amazon.com/certification/certified-security-specialty/)
-   [AWS Certified Solutions Architect - Associate](https://aws.amazon.com/certification/certified-solutions-architect-associate/)
-   [AWS Cloud Security](https://aws.amazon.com/security/)
-   [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/?cards-all.sort-by=item.additionalFields.sortDate&cards-all.sort-order=desc&awsf.content-type=*all&awsf.methodology=*all)
-   [AWS Security Learning](https://aws.amazon.com/security/security-resources/)
-   [AWS Vulnerabilities and the Attacker’s Perspective](https://rhinosecuritylabs.com/cloud-security/aws-security-vulnerabilities-perspective/)
-   [AzureGoat: A Damn Vulnerable Azure Infrastructure](https://github.com/ine-labs/AzureGoat?ref=thezentester.com)
-   [BadZure - Vulnerable Azure AD Lab](https://github.com/mvelazc0/BadZure?ref=thezentester.com)
-   [BishopFox: CloudFoxable](https://cloudfoxable.bishopfox.com/)
-   [Breaching the Cloud Perimeter](https://www.blackhillsinfosec.com/wp-content/uploads/2020/05/Breaching-the-Cloud-Perimeter-Slides.pdf)
-   [Dirkjan: Azure Security Blogs](https://dirkjanm.io/)
-   [Hacking Like a Ghost: Breaching the Cloud](https://nostarch.com/how-hack-ghost)
-   [Hacking The Cloud Encyclopedia](https://hackingthe.cloud/)
-   [HackTheBox: AWS Penetration Testing](https://www.hackthebox.com/blog/aws-pentesting-guide)
-   [HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html)
-   [Internal All The Things - Cloud](https://swisskyrepo.github.io/InternalAllTheThings/)
-   [Pentesting Azure Applications](https://nostarch.com/azure)
-   [PurpleCloud: Cyber Rank - Azure](https://www.purplecloud.network/?ref=thezentester.com)
-   [Rhino Security Labs: CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat?ref=thezentester.com)
-   [ROADTools - Azure AD Interaction Framework](https://github.com/dirkjanm/ROADtools)
-   [SpecterOps: Azure Blog Posts](https://posts.specterops.io/tagged/azure)
-   [TryHackMe: Attacking and Defending AWS](https://resources.tryhackme.com/attacking-and-defending-aws)
-   [XPN Blog](https://blog.xpnsec.com/)
-   I’m not cloud focused… so use Google!

# Binary Reverse Engineering / Exploit Development

Binary Reverse Engineering is the process of disassembling and analyzing an application to understand how it works in order to either exploit it, or to find specific vulnerabilities. This practice is now frequently utilized by Red Teamers or Exploit Developers when looking for 0days, or during engagements in certain industries, or even when source code isn’t provided. Through reverse engineering one can reveal how an application performs certain operations, handles data, or writes to memory, often using tools like [IDA Pro](https://www.hex-rays.com/products/ida/), [Binary Ninja](https://binary.ninja/), and [Ghidra](https://ghidra-sre.org/).

A common misconception is that reverse engineering is only associated with malware analysis, such as in the [WannaCry Malware](https://www.endgame.com/blog/technical-blog/wcrywanacry-ransomware-technical-analysis) to fully understand how the malware functions, but that’s really not the case! Malware is essentially just another application, and the process of reverse engineering it is no different than analyzing any other program, in the end you’re still reversing an application… just a malicious one.

Take this for example, the [1-day exploit development for Cisco IOS](https://media.ccc.de/v/34c3-8936-1-day_exploit_development_for_cisco_ios) used reverse engineering and debugging to exploit a vulnerability in Cisco Routers, something that can’t be done through simple fuzzing or black box pentesting.

As a penetester, having a basic understanding of reverse engineering and exploit development will likely be beneficial, especially for engagements that require advanced research. You’ll use these skills to understand how applications functions when source code is not provided, which is particularly useful when working with embedded systems or hardware devices. You may also find yourself dealing with more complex targets like BIOS/SMM, virtualization environments, containers, secure boot processes, and more.

To excel in these tasks, you’ll need a solid grasp of assembly languages for both x86 and x64 architectures, possibly MIPS too, along with a deep understanding of how the stack, heap, and memory allocation work. Additionally, knowledge of low-level operating system internals is extremely helpful for tackling these types of challenges.

While the learning curve for this specialty is usually very high, and it does take some time to be proficient in it - but once you’ve mastered it, it can be considered as a nuclear bomb in your arsenal. You can then officially call yourself a full-fledged hakzor! Additionally, this expertise can open up new career paths that allow you to transition into roles such as Security Research or Malware Reverse Engineering.


### Resources

-   [Architecture 1001: x86-64 Assembly](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Arch1001_x86-64_Asm+2021_v1/about)
-   [Architecture 2001: x86-64 OS Internals](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Arch2001_x86-64_OS_Internals+2021_v1/about)
-   [Awesome List: Reverse Engineering, Exploitation, and More!](https://github.com/0xor0ne/awesome-list)
-   [Awesome Reversing](https://github.com/ReversingID/Awesome-Reversing)
-   [COMPSCI 390R: Reverse Engineering & Vulnerability Analysis](https://pwn.umasscybersec.org/index.html)
-   [CrackMe Challanges](https://crackmes.one/)
-   [Debuggers 1011: Introductory WinDbg](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Dbg1011_WinDbg1+2021_v1/about)
-   [Debuggers 1012: Introductory GDB](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Dbg1012_GDB_1+2021_v1/about)
-   [Debuggers 1101: Introductory IDA](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Dbg1101_IntroIDA+2024_v1/about)
-   [Debuggers 1102: Introductory Ghidra](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Dbg1102_IntroGhidra+2024_v2/about)
-   [Debuggers 2011: Intermediate WinDbg](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Dbg2011_WinDbg2+2021_v1/about)
-   [Diary of a Reverse Engineer](https://doar-e.github.io/)
-   [Exploit Club Blog](https://blog.exploits.club/)
-   [Exploit Education](https://exploit.education/)
-   [Exploit Exercises](https://exploit-exercises.com/)
-   [FuzzySec - Part 1: Introduction to Exploit Development](https://fuzzysecurity.com/tutorials/expDev/1.html)
-   [Getting Started with Reverse Engineering](https://jlospinoso.github.io/developing/software/software%20engineering/reverse%20engineering/assembly/2015/03/06/reversing-with-ida.html)
-   [GitHub: Awesome Reversing](https://github.com/ReversingID/Awesome-Reversing)
-   [GitHub: Fuzzing-101](https://github.com/antonio-morales/Fuzzing101)
-   [GitHub: Fuzzing Lab (ACM Cyber)](https://github.com/pbrucla/fuzzing-lab)
-   [Guided Hacking: Game Hacking Forum](https://guidedhacking.com/)
-   [HackDay: LEARN TO REVERSE ENGINEER X86\_64 BINARIES](https://hackaday.com/2018/01/06/getting-acquainted-with-x86_64-binaries/)
-   [Hacking, The Art of Exploitation 2nd Edition](https://nostarch.com/hacking2.htm)
-   [Hasherezade: How to Start RE/Malware Analysis](https://hshrzd.wordpress.com/how-to-start/)
-   [IDA Pro Book, 2nd Edition](https://nostarch.com/idapro2.htm)
-   [Introduction to Reverse Engineering with Ghidra](https://hackaday.io/course/172292-introduction-to-reverse-engineering-with-ghidra)
-   [Introduction To Reverse Engineering Software](http://opensecuritytraining.info/IntroductionToReverseEngineering.html)
-   [Introduction To Software Exploits](http://www.opensecuritytraining.info/Exploits1.html)
-   [Introductory Intel x86-64: Architecture, Assembly, Applications, & Alliteration](http://opensecuritytraining.info/IntroX86-64.html)
-   [Introductory Intel x86: Architecture, Assembly, Applications, & Alliteration](http://opensecuritytraining.info/IntroX86.html)
-   [LiveOverflow Videos](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w/videos)
-   [MalwareUnicorn: Workshops](https://malwareunicorn.org/#/workshops)
-   [Nightmare: Into to Binary Exploitation](https://guyinatuxedo.github.io/index.html)
-   [OALabs: Malware Reverse Engineering](https://www.youtube.com/@OALABS)
-   [Off By One Secxurity: Vulnerability Research & Exploit Dev](https://www.youtube.com/@OffByOneSecurity)
-   [Offensive Security & Reverse Engineering Course](https://exploitation.ashemery.com/)
-   [0x00 Sec: Exploit Development](https://0x00sec.org/c/exploit-development/53)
-   [0x00 Sec: Reverse Engineering](https://0x00sec.org/c/reverse-engineering/58)
-   [Practical Binary Analysis](https://nostarch.com/binaryanalysis)
-   [PWN College](https://pwn.college/)
-   [RET2 Wargames](https://wargames.ret2.systems/)
-   [POP Emporium: Learn ROP Exploit Development](https://ropemporium.com/index.html)
-   [Reverse Engineering 3011: Reversing C++ Binaries](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+RE3011_re_cpp+2022_v1/about)
-   [Reverse Engineering 3201: Symbolic Analysis](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+RE3201_symexec+2021_V1/about)
-   [Reverse Engineering Resources](https://github.com/wtsxDev/reverse-engineering)
-   [Secret Club: Reverse Engineering Blog](https://secret.club/)
-   [The Shellcoder’s Handbook: Discovering and Exploiting Security Holes](https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X)
-   [Unknown Cheats: Game Hacking Forum](https://www.unknowncheats.me/forum/index.php)
-   [wtsxDev - Reverse Engineering Resources](https://github.com/wtsxDev/reverse-engineering)
-   Oh look…. Google!


# Hardware/Embedded Devices Hacking

Following closely in the footsteps of Reverse Engineering is the world of Hardware and Embedded Device security. With a solid understanding of hardware, electronics, and ARM architecture, you’ll find yourself in demand for roles that involve dissecting everything from routers and smart devices to lightbulbs and even cars.

With the increase in the development of IoT devices there is now a raised interest and controversy about the security of such systems. Let’s take the [Mirai Malware](https://krebsonsecurity.com/2016/10/who-makes-the-iot-things-under-attack/) as an example, which exploited insecure devices that were easily accessible on the internet. With a ton of insecure devices open on the internet, a company is simply one device away from a breach. Yah, just one device, for example when a [casino got hacked through its internet connected fish tank](https://thehackernews.com/2018/04/iot-hacking-thermometer.html).

Embedded systems are everywhere, from everyday household items to industrial machines. These systems typically run on [microcontrollers](https://en.wikipedia.org/wiki/Microcontroller), which means that some knowledge of computer and electronics is essential.

As a pentester, if you’re doing any hardware or embedded device security, you’ll need to become familiar with concepts such as [SPI](https://en.wikipedia.org/wiki/Serial_Peripheral_Interface), reading [schematics](https://en.wikipedia.org/wiki/Schematic), [FPGA](https://en.wikipedia.org/wiki/Field-programmable_gate_array), [UART](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver-transmitter), and [JTAG](https://en.wikipedia.org/wiki/JTAG). Understanding how to use tools like a [multimeter](https://en.wikipedia.org/wiki/Multimeter) and a [soldering iron](https://en.wikipedia.org/wiki/Soldering_iron) will be crucial for tasks like probing circuits or reworking hardware. It’s also helpful to have a good understanding of basic electronic components such as resistors, capacitors, switches, and transistors.

Also knowing the x86/x64 ASM, MIPS, and [ARM](https://en.wikipedia.org/wiki/ARM_architecture) architectures will greatly enhance your ability in testing such devices. Once you can extract the system image from [flash memory](https://en.wikipedia.org/wiki/Flash_memory) or gain access to the source code, you’ll be able to uncover vulnerabilities or exploit weaknesses.

Just like Reverse Engineering, the learning curve for embedded device security can be steep. However, once you grasp the basics everything starts to fall into place, and your expertise grows through hands-on experience. Honestly the best way to learn is by jumping into the fire and learning as you go.

### Resources

-   [Awesome Embedded and IoT Security](https://github.com/fkie-cad/awesome-embedded-and-iot-security)
-   [Azeria Labs - ARM Tutorials](https://azeria-labs.com/)
-   [Car Hackers Handbook: A Guide for the Penetration Tester](https://nostarch.com/carhacking)
-   [Coursera: Introduction to the Internet of Things and Embedded System](https://www.coursera.org/learn/iot)
-   [DEF CON 24 Internet of Things Village: Reversing and Exploiting Embedded Devices](https://www.youtube.com/watch?v=r4XntiyXMnA)
-   [EEVBlog Videos](https://www.youtube.com/user/EEVblog/videos)
-   [Exploit: Hands On IoT Hacking EBook](https://store.expliot.io/products/hands-on-internet-of-things-hacking)
-   [Flashback Team: Extracting Firmware from Embedded Devices](https://www.youtube.com/watch?v=nruUuDalNR0)
-   [GreatScott! Videos - Awesome Electronics Tutorials, Projects and How To’s](https://www.youtube.com/user/greatscottlab)
-   [Hackaday Hardware Hacking](https://hackaday.com/tag/hardware-hacking/)
-   [HardBreak: Hardware Hacking Wiki](https://www.hardbreak.wiki/)
-   [Hardware 1101: Intel SPI Analysis](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+hw1101_intel_spi+2023_v1/about)
-   [How to Read a Schematic](https://learn.sparkfun.com/tutorials/how-to-read-a-schematic)
-   [Introduction to ARM](https://opensecuritytraining.info/IntroARM.html)
-   [Introduction To Basic Electronics](https://www.makerspaces.com/basic-electronics/)
-   [IoT Security 101](https://github.com/V33RU/IoTSecurity101)
-   [LiveOverflow Videos - Riscure Embedded Hardware CTF](https://www.youtube.com/playlist?list=PLhixgUqwRTjwNaT40TqIIagv3b4_bfB7M)
-   [Matt Brown YouTube Videos](https://www.youtube.com/@mattbrwn/videos)
-   [Micro Corruption Embedded CTF](https://microcorruption.com/)
-   [Microcontroller Exploits](https://nostarch.com/microcontroller-exploits)
-   [OWASP Internet Of Things](https://owasp.org/www-project-internet-of-things/)
-   [Practical Firmware Reversing and Exploit Development for AVR-based Embedded Devices](https://github.com/radareorg/radareorg/blob/master/source/_files/avrworkshops2016.pdf)
-   [Practical IoT Hacking](https://nostarch.com/practical-iot-hacking)
-   [Rapid7: Hands-On IoT Hacking](https://www.rapid7.com/globalassets/_pdfs/final-hands-on-iot-whitepaper-.pdf)
-   [Reading Silicon: How to Reverse Engineer Integrated Circuits](https://www.youtube.com/watch?v=aHx-XUA6f9g)
-   [Reverse Engineering Flash Memory for Fun and Benefit](https://www.blackhat.com/docs/us-14/materials/us-14-Oh-Reverse-Engineering-Flash-Memory-For-Fun-And-Benefit-WP.pdf)
-   [Reverse Engineering Hardware of Embedded Devices](https://www.sec-consult.com/en/blog/2017/07/reverse-engineering-hardware-of-embedded-devices-from-china-to-the-world/)
-   [Rhyme-2016 Hardware Hacking Challange](https://github.com/Riscure/Rhme-2016)
-   [The Hardware Hacking Handbook](https://nostarch.com/hardwarehacking)
-   [VoidStar Security Research Blog](https://voidstarsec.com/blog/)
-   [WrongBaud Blog](https://wrongbaud.github.io/)
-   Google…. Like I shouldn’t even have to mention this!


# Physical Hacking

You can have the most advanced security systems, the most hardened infrastructure, and the best security team in the world, but none of that matters if an attacker can simply carry out your servers through the front door. This is where Physical Security comes in!

It’s something unheard of, hackers breaking into companies… through the FRONT DOOR! \*_[dun dun duuuunnnn](https://www.youtube.com/watch?v=cphNpqKpKc4)\*_ Yah, scary, I know!

But honestly, really take a second to assess this matter. We spend so much time and resources securing our computer systems, web applications, and networks, but we often overlook the vulnerability that comes from the human and physical aspects. Anyone can just walk right into a company that has improper security controls and steal data, plant malware, or even carry out destructive actions.

As a pentester conducting a physical security assessment, you’ll need to understand a wide range of subjects. This includes everything from the psychology of human behavior, surveillance techniques, and lock picking to RFID security, camera systems, and universal keys. During a general assessment, you’ll typically survey the physical location, identify entry and exit points, and evaluate the effectiveness of existing security measures, such as guards, cameras, pressure sensors, motion detectors, and tailgating defenses.

After that you’ll be required to break into the building via methods like lock picking (if in scope), tailgating, destructive entry (rarely in scope…) and even social engineering. Once inside you will be required to carry out certain objectives likes stealing a laptop, or connecting a [dropbox](https://www.blackhillsinfosec.com/how-to-build-your-own-penetration-testing-drop-box/), to even sitting at someone’s desk - like the CEO’s!

It’s almost as if you were a full-fledged spy! While this may sound exciting, it’s actually quite challenging to execute. You need a solid understanding of human psychology, body language, and social cues, and understand how different locks and security mechanisms work. If you’re not good with people, or get really nervous when lying, then maybe this isn’t for you, but it’s still worth learning and can be a valuable skill to have!


### Resources

-   [10 Psychological Studies That Will Boost Your Social Life](https://thequintessentialmind.com/10-psychological-studies-that-will-boost-your-social-life/)
-   [Awesome Lockpicking](https://github.com/meitar/awesome-lockpicking)
-   [Awesome Physical Security](https://github.com/rustrose/awesome-physec)
-   [Body Language vs. Micro-Expressions](https://t.co/PSOFkCLJgL)
-   [CONFidence 2018: A 2018 practical guide to hacking RFID/NFC (Sławomir Jasek)](https://www.youtube.com/watch?v=7GFhgv5jfZk)
-   [Deviant Ollam Youtube](https://www.youtube.com/user/DeviantOllam/videos)
-   [Lock Bypass](http://www.lockwiki.com/index.php/Bypass)
-   [Lock Wiki](http://www.lockwiki.com/index.php/Main_Page)
-   [Lockpicking - by Deviant Ollam](https://deviating.net/lockpicking/presentations.html)
-   [Lockpicking 101](https://www.itstactical.com/skillcom/lock-picking/lock-picking-101/)
-   [Locksport: A Hacker’s Guide to Lockpicking, Impressioning, and Safe Cracking](https://nostarch.com/locksport)
-   [Practical Social Engineering](https://nostarch.com/practical-social-engineering)
-   [Psychological Manipulation Wiki](https://en.m.wikipedia.org/wiki/Psychological_manipulation)
-   [Red Team: How to Succeed By Thinking Like the Enemy](https://www.amazon.com/Red-Team-Succeed-Thinking-Enemy/dp/1501274899)
-   [RFID Cloning](https://www.getkisi.com/blog/how-to-copy-access-cards-and-keyfobs)
-   [The Dictionary of Body Language: A Field Guide to Human Behavior](https://www.amazon.com/Dictionary-Body-Language-Field-Behavior-ebook/dp/B075JDX981)
-   [The Ethics of Manipulation](https://plato.stanford.edu/entries/ethics-manipulation/)
-   [TOOOL: The Open Organisation Of Lockpickers](https://toool.us/)
-   [UFMCS, “The Applied Critical Thinking Handbook”](https://fas.org/irp/doddir/army/critthink.pdf)
-   [Unauthorised Access: Physical Penetration Testing For IT Security Teams](https://www.amazon.com/Unauthorised-Access-Physical-Penetration-Security/dp/0470747617)
-   [What Every Body Is Saying: An Ex-FBI Agent’s Guide to Speed-Reading People](https://www.amazon.com/What-Every-Body-Saying-Speed-Reading/dp/0061438294)
-   [Youtube: LockPickingLawyer](https://www.youtube.com/c/lockpickinglawyer/videos)
-   Lockpicking Village at Hacker Conferences!
-   Google & YouTube…
