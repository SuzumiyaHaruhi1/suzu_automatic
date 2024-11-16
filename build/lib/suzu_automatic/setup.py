from setuptools import setup, find_packages

setup(
    name="suzu-automatic",
    version="1.0.0",
    description="Набор инструментов автоматизации для CTF и пентеста",
    author="Suzumiya Haruhi",
    url="https://github.com/SuzumiyaHaruhi1/suzu_automatic",
    packages=find_packages(),
    install_requires=[
        "colorama==0.4.4",
        "Flask==3.1.0",
        "hexdump==3.3",
        "impacket==0.11.0",
        "lxml==4.6.3",
        "paramiko==3.4.0",
        "psutil==5.8.0",
        "requests==2.31.0",
        "scapy==2.5.0",
        "tabulate==0.9.0",
        "urllib3==2.2.3",
    ],
    entry_points={
        "console_scripts": [
            "suzu=suzu_automatic.suzu:main",
        ],
    },
)
