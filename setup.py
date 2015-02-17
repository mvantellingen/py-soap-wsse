from setuptools import find_packages, setup


setup(
    name='soap_wsse',
    version='0.1.0',
    install_requires=[
        'dm.xmlsec.binding==1.3.2',
        'lxml>=3.0.0',
        'pyOpenSSL>=0.14',
        'suds-jurko>=0.6',
    ],
    tests_require=[
    ],
    entry_points={
    },
    package_dir={'': 'src'},
    packages=find_packages('src'),
    include_package_data=True,
    license='proprietary',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: Other/Proprietary License',
    ],
    zip_safe=False,
)
