from setuptools import setup, find_packages

setup(
    name="dns_query_tool",
    version="1.0",
    description="A GUI DNS query tool with response time visualization and mail server health checks",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "dnspython>=2.2.0",
        "matplotlib>=3.5.0",
    ],
    entry_points={
        'console_scripts': [
            'dns_query_tool=dns_query_tool.main:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
