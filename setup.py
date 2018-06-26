from distutils.core import setup, Extension

vips_vipstar_module = Extension('vips_vipstar',
                            sources = ['vipstar.c'],
                            extra_compile_args=['-march=native', '-funroll-loops', '-fomit-frame-pointer'],
                            include_dirs=['.'])

setup (name = 'vips_vipstar',
       version = '1.0',
       description = 'Bindings for vipstar proof of work used by vipstarcoin',
       ext_modules = [vips_vipstar_module])
