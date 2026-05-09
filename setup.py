from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    install_requires = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name             = "captcharecon",
    version          = "1.0.0",
    author           = "Ariful Islam Mazumdar",
    author_email     = "1fehrnandez@gmail.com",
    description      = "CAPTCHA & Anti-Automation Reconnaissance Toolkit for authorised web app pentesting",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url              = "https://github.com/arif-offsec/captcharecon",
    license          = "GPL-3.0",
    packages         = find_packages(),
    python_requires  = ">=3.8",
    install_requires = install_requires,
    entry_points     = {
        "console_scripts": [
            "captcharecon=captcharecon.cli:main",
        ],
    },
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
    ],
    keywords = (
        "captcha recon pentesting web-security burp-suite caido "
        "waf bot-detection anti-automation security-research"
    ),
)
