from setuptools import find_packages, setup


description = """
Simply library to sign and verify SOAP XML requests using the
BinarySecurityToken specification.
""".strip()

setup(
    name='soap_wsse',
    version='0.1.1',
    description=description,
    install_requires=[
        'dm.xmlsec.binding==1.3.2',
        'lxml>=3.0.0',
        'pyOpenSSL>=0.14',
        'suds-jurko>=0.6',
    ],
    tests_require=[
        'py.test',
        'pytest-cov',
    ],
    entry_points={
    },
    package_dir={'': 'src'},
    packages=find_packages('src'),
    include_package_data=True,
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
    ],
    zip_safe=False,
)
