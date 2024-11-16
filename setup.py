from setuptools import setup, find_packages

setup(
    name="suzu_automatic",
    version="1.0.0",
    author="Suzumiya Haruhi",
    description="Набор инструментов автоматизации для CTF и пентеста",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/SuzumiyaHaruhi1/suzu_automatic",
    packages=find_packages(exclude=["*.db"]),
    include_package_data=True,
    install_requires=open('requirements.txt').read().splitlines(),
    entry_points={
        'console_scripts': [
            'suzu=suzu:main',  # Основная точка входа
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    },
    python_requires='>=3.8',
)
