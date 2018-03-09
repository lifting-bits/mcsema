int foo (void)
{
    return 42;
}

int bar (int i)
{
    return foo () + i;
}

int baz (void)
{
    return bar (8) + 1;
}

int test (int i)
{
    if (i < 1)
        return 0;
    else
        return i + test (i-1);
}
