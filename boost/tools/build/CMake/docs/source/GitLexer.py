import pygments.lexer
from pygments.lexer import RegexLexer, bygroups, using
from pygments.token import *

class GitCmdLineLexer(RegexLexer):
    aliases = ['git_cmdline']

    filenames = []

    kwds = r'(?:log|reset|config|clone|status|remote|add|push|branch|pull|checkout|merge|rebase|diff|commit|fetch|symbolic-ref|svn|init|format-patch)\s';

    tokens = {
        'root' : [
         (r'(/\w+)+', Generic.Constant),
         (kwds, Generic.Deleted),
         (r'(?:git|http)(?:@|://)[^\s]+\.git', Literal.String),
         (r'\'[^\']+\'', Literal.String), # current branch
         (r'\*\s\w+\n', Name.Label), # current branch
         (r'-\w+ ', Operator),
         (r'/[\w\./]+', Name.Variable),
         (r'git', Text),
         (r'% git', Keyword),
         (r'\*', Operator),
         (r'\s', Generic.Whitespace),
         (r'[^\s]+', Text)
         ]
    }


class GitLexer(RegexLexer):
    name = "GitLexer"
    aliases = ['git_shell']

    filenames = []

    tokens = {
        'root' : [
        (r'% git.*\n', using(GitCmdLineLexer)),
        (r'(% )(.*\n)', bygroups(Keyword, Text)),
        (r'[^\n\s]+', Generic.Output),
        (r'[\n\s]+', Generic.Whitespace)
        ]
    }

gitlexer = GitLexer()

def setup(app):
    app.add_lexer('git_shell', gitlexer)

