# Manual for `send_template_mail.py`

This script enables you to send personalized mails to multiple persons, taking the data
from a single CSV (comma separated value) file and another template mail. Its primary
use case is to send the ESI (`ErstSemesterInformant`) of the student council of the
Faculty of Technology to the new first-years. Usually their data are handed to us in an
excel file which can be converted easily to a CSV file.

Since the number of new first-years is growing continuously (even after the beginning of
the semester) the `ESI` must be sent in multiple waves in order to be delivered as soon
as possible but also to be sent to everyone. The script can save the `MD5`-hash of used
mail addresses, so you're able to use the updated table of first-years data without
resending mails. See the example section.

This manual is only an extension of the help message of the script
(`send_template_mail.py --help`) which should be your starting point in case of
questions.

 A `resources` folder should be located next to the real location of the script (*real*
 since the path you call might be a symlink).

## Command line arguments from files

Since the script offers a lot of command line arguments, some of which you might want to
reuse, you can pass any amount of command line arguments via text files. Simply specify
the file names via `@<filename>`, for example if you'd like to test the send process
without actually sending the mails you can use a python debug server (see
`help`-message) and specify the necessary args via `send_template_mail.py [...]
@resources/smtp_test_args [...]`. Inside the file you must the `--long-option=value`
format.
The `.gitignore` of this repo explicitly contains the path `/local_resources/`
which you can use to store your local settings.

## Hash file

As written above, this mechanism allows you to save the mail addresses of previous
recipients in a privacy friendly manner by only storing the MD5-hash of it.

Its format ist simple: one hash per line and comments are recognized by a leading '#'.
Whenever one or multiple values are added to the file a timestamp is written as well.

If you forgot to specify the hash file (and ignored the corresponding warning) you do
not have to create it by hand, instead rerun the script but use a debugging smtp server
to not send the mails to the actual recipients (again, see `help` message) and this time
pass a path to the hash file.

## Examples

### Filters

The goal of the filters is to enable you to use the CSV file as given and not having to
filter and split in multiple files.

In 2018 all female first-years received a slight different mail mentioning a
mentoring program and the corresponding flyer as attachment. The CSV file had
a column called `Geschlecht` with the values `männlich` and `weiblich` (because it's
only binary... different discussion^^) so the corresponding script calls would be:

```shell
$ ./send_template_mail.py file.csv 'Subject' m_template.txt --filter Geschlecht '^m' ...
```

```shell
$ ./send_template_mail.py file.csv 'Subject' f_template.txt --filter Geschlecht '^w' ...
```

## Full Example

Try it with the given test data inside the resources folder and a debug server.

```shell
$ ./send_template_mail.py resources/test_data.csv 'Subject' resources/test.template \
  -e Mail @resources/smtp_test_args -f 'Your Name' 'test@example.com'
```

Your debug server should have received two mails, one should be base64 due to the `ä`
inside `männlich`.

Let's try female (`weiblich` in German) only

```shell
$ ./send_template_mail.py resources/test_data.csv 'Subject' resources/test.template \
  -e Mail @resources/smtp_test_args --filter Geschl ^w -f 'Your Name' 'test@example.com'

```

Only one mail is sent and the script tells you which entries were skipped due to the
filter (`^w` only matches strings starting with a `w`).


### 2018

The full call has been:

```shell
$ ./send_template_mail.py erstis_m_final.csv \
  'Informationen zum Studienbeginn und Vorkursen' studenten.template -e Mail \
  -f "Student Council" "redacted@example.de" -a ~/Downloads/ESI.pdf \
  ~/Downloads/Vorkurse_und_StART.pdf | tee erstis_m.log
```

- The `filter` functionality was not present yet, therefore the data had to be separated
into male and female first-years.
- The `-l/--log-output` was not present yet and the logging messages were written to
STDOUT and saved via `tee`
- Same goes for the hash-file
