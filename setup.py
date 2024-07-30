from setuptools import setup, find_packages
setup(
    name='ShurikenAnalyzer',
    version='1.0.0',
    author='Fare9',
    author_email='your.email@example.com',
    description='A library focused on binary analysis (mainly for Java related bytecodes)',
    packages=find_packages("shuriken/include/shuriken/api/Python"),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.6',
)
