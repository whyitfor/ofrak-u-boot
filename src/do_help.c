extern int do_version_meow(void);

int do_help(void) {
    int ret = do_version_meow();
    return ret;
}
