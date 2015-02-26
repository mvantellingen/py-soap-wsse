from setuptools import find_packages, setup


description = """
Simply library to sign and verify SOAP XML requests using the
BinarySecurityToken specification.
""".strip()

setup(
    name='soap_wsse',
    version='0.2.0',
    description=description,
    url='https://github.com/mvantellingen/py-soap-wsse',
    author="Michael van Tellingen",
    author_email="michaelvantellingen@gmail.com",
    install_requires=[
        'dm.xmlsec.binding==1.3.2',
        'lxml>=3.0.0',
        'pyOpenSSL>=0.14',
    ],
    tests_require=[
        'py.test',
        'pytest-cov',
        'pretend>=1.0.0',
        'suds-jurko>=0.6',
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
