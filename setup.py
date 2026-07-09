from setuptools import setup, find_packages

setup(
    name='pyzbar',
    version='0.1.9.post1',
    description=(
        'Rho-9 hardened fork of pyzbar - reads barcodes/QR codes via '
        'zbar, with input validation and process-isolated decoding added.'
    ),
    packages=find_packages(include=['pyzbar', 'pyzbar.*']),
    package_data={
        'pyzbar': ['tests/*.png', 'SECURITY_NOTES.md'],
    },
    entry_points={
        'console_scripts': [
            'read_zbar=pyzbar.scripts.read_zbar:main',
        ],
    },
    python_requires='>=3.7',
    extras_require={
        'scripts': ['Pillow'],
        'test': ['Pillow', 'numpy'],
    },
)
