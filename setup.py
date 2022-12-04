#!/usr/bin/env python

from setuptools import setup
import pathlib

here = pathlib.Path(__file__).parent.resolve()
long_description = (here / "README.md").read_text(encoding="utf-8")
install_requires = (here / "requirements.txt").read_text(encoding="utf-8").splitlines()

setup(
    name="fb_login_brute",
    version="1.0.0",
    description="Facebook login Brute force Attack",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Tibotix",
    author_email="tizian@seehaus.net",
    url="https://github.com/tibotix/fb_login_brute",
    package_dir={"fb_login_brute": "src"},
    packages=["fb_login_brute"],
    install_requires=install_requires,
    entry_points={
        "console_scripts": ["fb_login_brute=fb_login_brute.login_brute:main"]
    },
    python_requires=">=3.8, <4",
)