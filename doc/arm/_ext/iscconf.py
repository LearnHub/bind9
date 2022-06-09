############################################################################
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
############################################################################

"""
Sphinx domains for ISC configuration files.

Use setup() to install new Sphinx domains for ISC configuration files.

This extension is based on combination of two Sphinx extension tutorials:
https://www.sphinx-doc.org/en/master/development/tutorials/todo.html
https://www.sphinx-doc.org/en/master/development/tutorials/recipe.html
"""

from collections import namedtuple

from docutils.parsers.rst import directives
from docutils import nodes

from sphinx import addnodes
from sphinx.directives import ObjectDescription
from sphinx.domains import Domain
from sphinx.roles import XRefRole
from sphinx.util.nodes import make_refnode
from sphinx.util.docutils import SphinxDirective


def split_csv(argument, required):
    argument = argument or ""
    outlist = list(filter(len, (s.strip() for s in argument.split(","))))
    if required and not outlist:
        raise ValueError(
            "a non-empty list required; provide at least one value or remove"
            " this option"
        )
    return outlist


# pylint: disable=too-many-statements
def domain_factory(domainname, domainlabel, todolist):
    """
    Return parametrized Sphinx domain object.
    @param domainname Name used when referencing domain in .rst: e.g. namedconf
    @param confname Humand-readable name for texts, e.g. named.conf
    @param todolist A placeholder object which must be pickable.
                    See StatementListDirective.
    """

    class StatementListDirective(SphinxDirective):
        """A custom directive to generate list of statements.
        It only installs placeholder which is later replaced by
        process_statementlist_nodes() callback.
        """

        def run(self):
            return [todolist("")]

    class ISCConfDomain(Domain):
        """
        Custom Sphinx domain for ISC config.
        Provides .. statement:: directive to define config statement and
        .. statementlist:: to generate summary tables.
        :ref:`statementname` works as usual.

        See https://www.sphinx-doc.org/en/master/extdev/domainapi.html
        """

        class StatementDirective(ObjectDescription):
            """
            A custom directive that describes a statement,
            e.g. max-cache-size.
            """

            has_content = True
            required_arguments = 1
            option_spec = {
                "tags": lambda arg: split_csv(arg, required=False),
                # one-sentece description for use in summary tables
                "short": directives.unchanged_required,
            }

            def handle_signature(self, sig, signode):
                signode += addnodes.desc_name(text=sig)
                return sig

            def add_target_and_index(self, _name_cls, sig, signode):
                signode["ids"].append(domainname + "-statement-" + sig)

                iscconf = self.env.get_domain(domainname)
                iscconf.add_statement(sig, self.isc_tags, self.isc_short)

            @property
            def isc_tags(self):
                return self.options.get("tags", [])

            @property
            def isc_short(self):
                return self.options.get("short", "")

            def transform_content(self, contentnode: addnodes.desc_content) -> None:
                """autogenerate content from structured data"""
                if self.isc_short:
                    contentnode.insert(0, nodes.paragraph(text=self.isc_short))
                if self.isc_tags:
                    tags = nodes.paragraph()
                    tags += nodes.strong(text="Tags: ")
                    tags += nodes.Text(", ".join(self.isc_tags))
                    contentnode.insert(0, tags)

        name = domainname
        label = domainlabel

        directives = {
            "statement": StatementDirective,
            "statementlist": StatementListDirective,
        }

        roles = {"ref": XRefRole(warn_dangling=True)}
        initial_data = {
            "statements": [],  # object list for Sphinx API
            # our own metadata: name -> {"tags": [list of tags], "short": "short desc"}
            "statements_extra": {},
        }

        indices = {}  # no custom indicies

        def get_objects(self):
            """Sphinx API: iterable of object descriptions"""
            for obj in self.data["statements"]:
                yield obj

        # pylint: disable=too-many-arguments
        def resolve_xref(self, env, fromdocname, builder, typ, target, node, contnode):
            """
            Sphinx API:
            Resolve the pending_xref *node* with the given typ and target.
            """
            match = [
                (docname, anchor)
                for name, sig, typ, docname, anchor, _prio in self.get_objects()
                if sig == target
            ]

            if len(match) == 0:
                return None
            todocname = match[0][0]
            targ = match[0][1]

            refnode = make_refnode(
                builder, fromdocname, todocname, targ, contnode, targ
            )
            return refnode

        def resolve_any_xref(self, env, fromdocname, builder, target, node, contnode):
            """
            Sphinx API:
            Raising NotImplementedError uses fall-back bassed on resolve_xref.
            """
            raise NotImplementedError

        def add_statement(self, signature, tags, short):
            """
            Add a new statement to the domain data structures.
            No visible effect.
            """
            name = "{}.{}.{}".format(domainname, "statement", signature)
            anchor = "{}-statement-{}".format(domainname, signature)

            self.data["statements_extra"][name] = {"tags": tags, "short": short}
            # Sphinx API: name, dispname, type, docname, anchor, priority
            self.data["statements"].append(
                (
                    name,
                    signature,
                    domainlabel + " statement",
                    self.env.docname,
                    anchor,
                    1,
                )
            )

        def clear_doc(self, docname):
            """
            Sphinx API: like env-purge-doc event, but in a domain.

            Remove traces of a document in the domain-specific inventories.
            """
            # use name->doc mapping from Sphinx metadata
            for name, _, _, cur_docname, _, _ in self.data["statements"]:
                if cur_docname == docname:
                    if name in self.data["statements_extra"]:
                        del self.data["statements_extra"][name]
            self.data["statements"] = list(
                obj for obj in self.data["statements"] if obj[3] != docname
            )

        def merge_domaindata(self, docnames, otherdata):
            """Sphinx API: Merge in data regarding *docnames* from a different
            domaindata inventory (coming from a subprocess in parallel builds).

            @param otherdata is self.data equivalent from another process

            Beware: As of Sphinx 4.5.0, this is called multiple times in a row
            with the same data and has to guard against duplicites.  It seems
            that all existing domains in Sphinx distribution have todo like
            "deal with duplicates" but do nothing about them, so we just follow
            the suite."""
            self.data["statements"] = list(
                set(self.data["statements"] + otherdata["statements"])
            )
            self.data["statements_extra"].update(otherdata["statements_extra"])

        @classmethod
        def process_statementlist_nodes(cls, app, doctree, fromdocname):
            """
            Replace todolist objects (placed into document using
            .. statementlist::) with automatically generated table
            of statements.
            """
            env = app.builder.env
            iscconf = env.get_domain(cls.name)

            table_header = [
                TableColumn("ref", "Statement name"),
                TableColumn("short", "Short desc"),
                TableColumn("tags", "Tags"),
            ]
            table_b = DictToDocutilsTableBuilder(table_header)
            table_b.append_iterable(iscconf.list_all(fromdocname))
            table = table_b.get_docutils()
            for node in doctree.traverse(todolist):
                node.replace_self(table)

        def list_all(self, fromdocname):
            for statement in self.data["statements"]:
                name, sig, _const, _doc, _anchor, _prio = statement
                extra = self.data["statements_extra"][name]
                short = extra["short"]
                tags = ", ".join(extra["tags"])

                refpara = nodes.inline()
                refpara += self.resolve_xref(
                    self.env,
                    fromdocname,
                    self.env.app.builder,
                    None,
                    sig,
                    None,
                    nodes.Text(sig),
                )

                yield {
                    "fullname": name,
                    "ref": refpara,
                    "short": short,
                    "tags": tags,
                }

    return ISCConfDomain


# source dict key: human description
TableColumn = namedtuple("TableColumn", ["dictkey", "description"])


class DictToDocutilsTableBuilder:
    """generate docutils table"""

    def __init__(self, header):
        """@param header: [ordered list of TableColumn]s"""
        self.header = header
        self.table = nodes.table()
        self.table["classes"] += ["colwidths-auto"]
        self.returned = False
        # inner nodes of the table
        self.tgroup = nodes.tgroup(cols=len(self.header))
        for _ in range(len(self.header)):
            # ignored because of colwidths-auto, but must be present
            colspec = nodes.colspec(colwidth=1)
            self.tgroup.append(colspec)
        self.table += self.tgroup
        self._gen_header()

        self.tbody = nodes.tbody()
        self.tgroup += self.tbody

    def _gen_header(self):
        thead = nodes.thead()

        row = nodes.row()
        for column in self.header:
            entry = nodes.entry()
            entry += nodes.Text(column.description)
            row += entry

        thead.append(row)
        self.tgroup += thead

    def append_iterable(self, objects):
        """Append rows for each object (dict), ir order.
        Extract column values from keys listed in self.header."""
        for obj in objects:
            row = nodes.row()
            for column in self.header:
                entry = nodes.entry()
                value = obj[column.dictkey]
                if isinstance(value, str):
                    value = nodes.Text(value)
                entry += value
                row += entry
            self.tbody.append(row)

    def get_docutils(self):
        # guard against table reuse - that's most likely an error
        assert not self.returned
        self.returned = True
        return self.table


def setup(app, domainname, confname, docutilsplaceholder):
    """
    Install new parametrized Sphinx domain.
    """

    Conf = domain_factory(domainname, confname, docutilsplaceholder)
    app.add_domain(Conf)
    app.connect("doctree-resolved", Conf.process_statementlist_nodes)

    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
