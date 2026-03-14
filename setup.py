from setuptools import setup, find_packages

setup(
    name='hashitout',
    version='4.0.0',
    description='Elite decoder, reverser, file rebuilder, stego scanner, and URL content analyzer',
    url='https://github.com/RRSWSEC/Hash-It-Out',
    packages=find_packages(),
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'hashitout=hashitout:main',
        ],
    },
    package_data={
        '': ['wordlists/*.txt'],
    },
)
