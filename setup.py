from setuptools import setup

setup(name='pyieee1905',
      version='0.1',
      description='IEEE1905 implementation using Python and Scapy',
      url='https://github.com/evanslai/pyieee1905',
      author='Evans Lai',
      author_email='evanslai@gmail.com',
      license='MIT',
      packages=['pyieee1905'],
      install_requires=[
          'scapy',
      ],
      zip_safe=False)

