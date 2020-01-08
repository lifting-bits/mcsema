/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>

struct Book
{
    char title [50];
    char author [50];
    char subject [100];
    int book_id;
};

void printBook (struct Book book);

int main ()
{
    struct Book Book1;
    struct Book Book2;

    strcpy (Book1.title,   "C Programming");
    strcpy (Book1.author,  "Nuha Ali");
    strcpy (Book1.subject, "C Programming Tutorial");
    Book1.book_id = 6495407;

    strcpy (Book2.title,   "Telecom Billing");
    strcpy (Book2.author,  "Zara Ali");
    strcpy (Book2.subject, "Telecom Billing Tutorial");
    Book2.book_id = 6495700;

    printBook (Book1);
    printBook (Book2);

    return 0;
}

void printBook (struct Book book)
{
    printf ("Book title:   %s\n", book.title);
    printf ("Book author:  %s\n", book.author);
    printf ("Book subject: %s\n", book.subject);
    printf ("Book book_id: %d\n", book.book_id);
    printf ("\n");
}
