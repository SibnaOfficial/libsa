#!/usr/bin/env python3
"""
Sibna Protocol Standalone Python SDK - Setup Script
"""

from setuptools import setup, find_packages
import os
import platform

version = "1.0.4"

# Package data (including the native library)
package_data = {
    "sibna": ["*.so", "*.dll", "*.dylib"],
}

setup(
    name="sibna",
    version=version,
    author="Sibna Security Team",
    author_email="security@sibna.dev",
    description="Standalone Ultra-Secure Communication Protocol - Python SDK",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    package_data=package_data,
    include_package_data=True,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.8",
    install_requires=[],
    keywords="cryptography encryption signal secure-messaging e2ee",
)
