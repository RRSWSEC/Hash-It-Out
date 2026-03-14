from setuptools import setup, find_packages

setup(
    name='hashitout',
    version='4.0.0',
    packages=find_packages(),
    install_requires=[],
    entry_points={'console_scripts': ['hashitout=hashitout:main']},
    python_requires='>=3.7',
    description='Elite decoder, reversing tool, stego scanner and URL content analyzer',
)
