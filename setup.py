from setuptools import setup, find_packages

setup(
    name="sqlInjection_Scanner",  # Package name
    version="1.0.0",  # Initial release version
    author="FlxBot001",  # Your name
    author_email="flxnjgn@gmail.com",  # Replace with your email address
    description="A Python package for detecting SQL injection vulnerabilities in web applications.",
    long_description=open('README.md').read(),  # Read the long description from README.md
    long_description_content_type='text/markdown',  # Format of the long description
    url="https://github.com/FlxBot001/sqlInjection_Scanner",  # Replace with your project URL
    packages=find_packages(),  # Automatically find and include all packages in the directory
    install_requires=[
        "requests==2.31.0",
        "beautifulsoup4==4.12.2",
        "validators==0.20.0",  # Add validators library
        "concurrent-log-handler==0.9.24",
        "urllib3==2.0.5",
        "numpy==1.25.0",
        "scikit-learn==1.3.0",
        "transformers==4.34.0",
        "sqlmap-python-api==1.6.3",
        # Add any other dependencies your project needs
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',  # Minimum Python version required
)

