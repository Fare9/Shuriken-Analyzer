import contextlib
import os
import platform
import subprocess
from pathlib import Path
from contextlib import contextmanager
from setuptools import setup, find_packages
from setuptools.command.build_ext import build_ext as _build_ext
from setuptools.command.sdist import sdist as _sdist
from setuptools.command.bdist_egg import bdist_egg as _bdist_egg
from setuptools.command.install import install as _install
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SUBFOLDERS_NUMBER=2
ROOT_FOLDER = Path(__file__).resolve().parents[SUBFOLDERS_NUMBER]
BUILD_FOLDER = ROOT_FOLDER / 'build'


@contextmanager
def change_directory(path: Path):
    current_dir = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(current_dir)


def build_libraries():
    """Function to compile the Shuriken library using CMake on Linux."""

    # Ensure our build folder exists
    BUILD_FOLDER.mkdir(parents=True, exist_ok=True)

    if platform.system() == 'Linux':
        try:
            with change_directory(BUILD_FOLDER):
                logger.info("Configuring with CMake...")
                subprocess.check_call(['cmake', '..', '-DCMAKE_BUILD_TYPE=Release'])

                logger.info("Building with CMake...")
                subprocess.check_call(['cmake', '--build', '.', '-j'])

                logger.info("Installing with CMake...")
                subprocess.check_call(['sudo', 'cmake', '--install', '.'])
        except subprocess.CalledProcessError as e:
            logger.error(f"Cmake build failed: {e}")
        except Exception as e:
            logger.error(f"An error ocurred: {e}")

    else:
        logger.warning("CMake build is only supported on Linux for now.")


class custom_sdist(_sdist):
    def run(self):
        super().run()


class custom_build_ext(_build_ext):
    def run(self):
        logger.info('Building C extensions...')
        build_libraries()
        super().run()


class custom_bdist_egg(_bdist_egg):
    def run(self):
        self.run_command('build_ext')
        super().run()

class CustomInstall(_install):
    def run(self):
        # Build the C++ extensions before installing Python package
        self.run_command('build_ext')
        super().run()


cmdclass = {
    'sdist': custom_sdist,
    'build_ext': custom_build_ext,
    'bdist_egg': custom_bdist_egg,
    'install': CustomInstall
}


setup(
    packages=['shuriken'],
    name='ShurikenAnalyzer',
    version='0.0.4',
    author='Fare9',
    author_email='kunai.static.analysis@gmail.com',
    description='Shuriken-Analyzer a library for Dalvik Analysis',
    url='https://github.com/Fare9/Shuriken-Analyzer',
    cmdclass=cmdclass,
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.10',
)