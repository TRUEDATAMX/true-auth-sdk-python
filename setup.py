from setuptools import setup, find_packages

setup(
    name="trueauth",
    version="0.1.0",
    author="TRUE Data Science & Engineering",
    author_email="luis@truedata.com.mx",
    description="Authentication SDK",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/TRUEDATAMX/true-auth-sdk-python",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",  # Minimum Python version
)
