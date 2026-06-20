from setuptools import setup, find_packages

setup(
    name="ssh-fortress",
    version="1.0.0",
    description="Modular SSH hardening, brute-force protection, and SIEM integration",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.10",
    install_requires=[
        "pyyaml>=6.0",
        "click>=8.1",
        "rich>=13.7",
        "colorlog>=6.8",
        "psutil>=5.9",
        "aiohttp>=3.9",
        "cryptography>=42.0",
        "netaddr>=0.10",
        "pydantic>=2.6",
    ],
    extras_require={
        "elasticsearch": ["elasticsearch>=8.12"],
        "kafka": ["kafka-python>=2.0"],
        "geoip": ["geoip2>=4.8", "maxminddb>=2.6"],
        "totp": ["pyotp>=2.9", "qrcode>=7.4"],
        "all": [
            "elasticsearch>=8.12", "kafka-python>=2.0",
            "geoip2>=4.8", "maxminddb>=2.6",
            "pyotp>=2.9", "qrcode>=7.4",
            "scapy>=2.5",
        ],
    },
    entry_points={
        "console_scripts": [
            "ssh-fortress=main:cli",
        ],
    },
)
