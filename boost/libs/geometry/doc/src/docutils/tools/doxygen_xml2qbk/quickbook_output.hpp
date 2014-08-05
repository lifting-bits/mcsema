// Boost.Geometry (aka GGL, Generic Geometry Library)
//
// Copyright (c) 2010-2012 Barend Gehrels, Amsterdam, the Netherlands.
// Use, modification and distribution is subject to the Boost Software License,
// Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
//
#ifndef QUICKBOOK_OUTPUT_HPP
#define QUICKBOOK_OUTPUT_HPP


#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>

#include <doxygen_elements.hpp>
#include <parameter_predicates.hpp>

std::string qbk_escaped(std::string const& s)
{
    // Replace _ by unicode to avoid accidental quickbook underlining.
    // 1) do NOT do this in quickbook markup, so not within []
    // (e.g. to avoid [include get_point.qbk] having unicoded)
    // 2) \[ and \] should not count as []
    std::size_t const len = s.length();
    int counter = 0;
    std::string result = "";
    for (std::size_t i = 0; i < len; i++)
    {
        switch(s[i])
        {
            case '[' : counter++; break;
            case ']' : counter--; break;
            case '\\' : 
                {
                    result += s[i];
                    if (i + 1 < len)
                    {
                        result += s[i + 1];
                    }
                    i++;
                    continue;
                }
            case '_' : 
                if (counter == 0)
                {
                    result += "\\u005f";
                    continue;
                }
        }
        result += s[i];
    }

    return result;
}



void quickbook_template_parameter_list(std::vector<parameter> const& parameters, std::ostream& out, bool name = false)
{
    if (!parameters.empty())
    {
        out << "template<" ;
        bool first = true;
        BOOST_FOREACH(parameter const& p, parameters)
        {
            out << (first ? "" : ", ") << p.fulltype;
            first = false;
        }
        out << ">" << std::endl;
    }
}


void quickbook_synopsis(function const& f, std::ostream& out)
{
    out << "``";
    quickbook_template_parameter_list(f.template_parameters, out);
    switch(f.type)
    {
        case function_constructor :
            out << f.name;
            break;
        case function_member :
            out << f.return_type << " " << f.name;
            break;
        case function_free :
            out << f.definition;
            break;
        case function_define :
            out << "#define " << f.name;
            break;
        case function_unknown :
            // do nothing
            break;
    }

    // Output the parameters
    // Because we want to be able to skip, we cannot use the argstring
    {
        bool first = true;
        BOOST_FOREACH(parameter const& p, f.parameters)
        {
            if (! p.skip)
            {
                out 
                    << (first ? "(" : ", ")
                    << p.fulltype << (p.fulltype.empty() ? "" : " ")
                    << p.name
                    << (p.default_value.empty() ? "" : " = ")
                    << p.default_value;
                first = false;
            }
        }
        if (! first)
        {
            out << ")";
        }
        else if (f.type != function_define)
        {
            out << "()";
        }
    }

    out << "``" 
        << std::endl
        << std::endl;
}


void quickbook_synopsis(enumeration const& e, std::ostream& out)
{
    out << "``enum " << e.name;
    bool first = true;
    BOOST_FOREACH(enumeration_value const& value, e.enumeration_values)
    {
        out << (first ? " {" : ", ") << value.name;
        if (! value.initializer.empty())
        {
            out << " = " << boost::trim_copy(value.initializer);
        }
        first = false;
    }
    if (! first)
    {
        out << "};";
    }
    out << "``" 
        << std::endl
        << std::endl;
}

inline bool includes(std::string const& filename, std::string const& header)
{
    std::string result;

    std::ifstream cpp_file(filename.c_str());
    if (cpp_file.is_open())
    {
        while (! cpp_file.eof() )
        {
            std::string line;
            std::getline(cpp_file, line);
            boost::trim(line);
            if (boost::starts_with(line, "#include")
                && boost::contains(line, header))
            {
                return true;
            }
        }
    }
    return false;
}


void quickbook_header(std::string const& location,
    configuration const& config,
    std::ostream& out)
{
    if (! location.empty())
    {
        std::vector<std::string> including_headers;

        // Select headerfiles containing to this location
        BOOST_FOREACH(std::string const& header, config.convenience_headers)
        {
            if (includes(config.convenience_header_path + header, location))
            {
                including_headers.push_back(header);
            }
        }

        out << "[heading Header]" << std::endl;
        if (! including_headers.empty())
        {
            out << "Either"
                << (including_headers.size() > 1 ? " one of" : "")
                << std::endl << std::endl;
            BOOST_FOREACH(std::string const& header, including_headers)
            {
                out << "`#include <" << config.start_include << header << ">`" << std::endl;
            }

            out << std::endl << "Or" << std::endl << std::endl;
        }
        out << "`#include <" << location << ">`" << std::endl;
        out << std::endl;
    }
}


void quickbook_markup(std::vector<markup> const& qbk_markup, 
            markup_order_type order, markup_type type, 
            std::ostream& out)
{
    bool has_output = false;
    BOOST_FOREACH(markup const& inc, qbk_markup)
    {
        if (inc.type == type && inc.order == order)
        {
            out << inc.value << std::endl;
            has_output = true;
        }
    }
    if (has_output)
    {
        out << std::endl;
    }
}



void quickbook_string_with_heading_if_present(std::string const& heading,
            std::string const& contents, std::ostream& out)
{
    if (! contents.empty())
    {
        out << "[heading " << heading << "]" << std::endl
            << qbk_escaped(contents) << std::endl
            << std::endl;
    }
}

inline std::string to_section_name(std::string const& name)
{
    // Make section-name lowercase and remove :: because these are filenames
    return boost::to_lower_copy(boost::replace_all_copy(name, "::", "_"));
}



void quickbook_short_output(function const& f, std::ostream& out)
{
    BOOST_FOREACH(parameter const& p, f.parameters)
    {
        if (! p.skip)
        {
            out << "[* " << p.fulltype << "]: ['" << p.name << "]:  " << p.brief_description << std::endl << std::endl;
        }
    }
    out << std::endl;
    out << std::endl;

    if (! f.return_description.empty())
    {
        out << "][" << std::endl;
        out << f.return_description << std::endl;
        out << std::endl;
    }

    out << std::endl;
}

inline std::string namespace_skipped(std::string const& name, configuration const& config)
{
    return config.skip_namespace.empty()
        ? name
        : boost::replace_all_copy(name, config.skip_namespace, "")
        ;
}

inline std::string output_if_different(std::string const& s, std::string const& s2)
{
    return boost::equals(s, s2)
        ? ""
        : s + " "
        ;
}

inline void quickbook_output_indexterm(std::string const& term, std::ostream& out
            //, std::string const& secondary = ""
            )
{
    out << "'''";
    if (boost::contains(term, "::"))
    {
        // "Unnamespace" it and add all terms (also namespaces)
        std::vector<std::string> splitted;
        std::string for_split = boost::replace_all_copy(term, "::", ":");
        boost::split(splitted, for_split, boost::is_any_of(":"), boost::token_compress_on);
        BOOST_FOREACH(std::string const& part, splitted)
        {
            out << "<indexterm><primary>" << part << "</primary></indexterm>";
        }
    }
    else
    {
        out << "<indexterm><primary>" << term;
        /*if (! secondary.empty())
        {
            out << "<secondary>" << secondary << "</secondary>";
        }*/
        out << "</primary></indexterm>";
    }
    out << "'''" << std::endl;
}

void quickbook_output(function const& f, configuration const& config, std::ostream& out)
{
    // Write the parsed function
    int arity = (int)f.parameters.size();

    std::string additional_description;

    if (! f.additional_description.empty())
    {
        additional_description = " (";
        additional_description += f.additional_description;
        additional_description += ")";
    }

    out << "[section:" << to_section_name(f.name);
    // Make section name unique if necessary by arity and additional description
    if (! f.unique)
    {
        out << "_" << arity;
        if (! f.additional_description.empty())
        {
            out << "_" << boost::to_lower_copy(boost::replace_all_copy(f.additional_description, " ", "_"));
        }
    }
    out << " " << f.name
        << additional_description
        << "]" << std::endl
        << std::endl;

    quickbook_output_indexterm(f.name, out);
        
    out << qbk_escaped(f.brief_description) << std::endl;
    out << std::endl;

    quickbook_string_with_heading_if_present("Description", f.detailed_description, out);

    // Synopsis
    quickbook_markup(f.qbk_markup, markup_before, markup_synopsis, out);
    out << "[heading Synopsis]" << std::endl;
    quickbook_synopsis(f, out);
    quickbook_markup(f.qbk_markup, markup_after, markup_synopsis, out);


    out << "[heading Parameters]" << std::endl
        << std::endl;

    out << "[table" << std::endl << "[";
    if (f.type != function_define)
    {
        out << "[Type] [Concept] ";
    }
    out << "[Name] [Description] ]" << std::endl;

    // First: output any template parameter which is NOT used in the normal parameter list
    BOOST_FOREACH(parameter const& tp, f.template_parameters)
    {
        if (! tp.skip)
        {
            std::vector<parameter>::const_iterator it = std::find_if(f.parameters.begin(), f.parameters.end(), par_by_type(tp.name));

            if (it == f.parameters.end())
            {
                out << "[[" << tp.name << "] [" << tp.brief_description << "] [ - ] [Must be specified]]" << std::endl;
            }
        }
    }

    BOOST_FOREACH(parameter const& p, f.parameters)
    {
        if (! p.skip)
        {
            out << "[";
            std::vector<parameter>::const_iterator it = std::find_if(f.template_parameters.begin(),
                f.template_parameters.end(), par_by_name(p.type));

            if (f.type != function_define)
            {
                out << "[" << p.fulltype
                    << "] [" << (it == f.template_parameters.end() ? "" : it->brief_description)
                    << "] ";
            }
            out << "[" << p.name
                << "] [" << p.brief_description
                << "]]"
                << std::endl;
        }
    }
    out << "]" << std::endl
        << std::endl
        << std::endl;

    quickbook_string_with_heading_if_present("Returns", f.return_description, out);

    quickbook_header(f.location, config, out);
    quickbook_markup(f.qbk_markup, markup_any, markup_default, out);

    out << std::endl;
    out << "[endsect]" << std::endl;
    out << std::endl;
}


void quickbook_output(enumeration const& e, configuration const& config, std::ostream& out)
{
    out << "[section:" << to_section_name(e.name);
    out << " " << e.name
        << "]" << std::endl
        << std::endl;

    quickbook_output_indexterm(e.name, out);
    BOOST_FOREACH(enumeration_value const& value, e.enumeration_values)
    {
        quickbook_output_indexterm(value.name, out);
    }

    out << e.brief_description << std::endl;
    out << std::endl;

    quickbook_string_with_heading_if_present("Description", e.detailed_description, out);

    // Synopsis
    quickbook_markup(e.qbk_markup, markup_before, markup_synopsis, out);
    out << "[heading Synopsis]" << std::endl;
    quickbook_synopsis(e, out);
    quickbook_markup(e.qbk_markup, markup_after, markup_synopsis, out);


    out << "[heading Values]" << std::endl
        << std::endl;

    out << "[table" << std::endl << "[";
    out << "[Value] [Description] ]" << std::endl;

    BOOST_FOREACH(enumeration_value const& value, e.enumeration_values)
    {
        out << "[[" << value.name
            << "] [" << value.brief_description
            << "]]"
            << std::endl;
    }
    out << "]" << std::endl
        << std::endl
        << std::endl;

    quickbook_header(e.location, config, out);
    quickbook_markup(e.qbk_markup, markup_any, markup_default, out);

    out << std::endl;
    out << "[endsect]" << std::endl;
    out << std::endl;
}

void quickbook_output_member(std::vector<function> const& functions, 
        function_type type, 
        std::string const& title,
        configuration const& config, std::ostream& out)
{
    std::string returns = type == function_constructor ? "" : " [Returns]";
    out << "[heading " << title << "(s)]" << std::endl
        << "[table" << std::endl
        << "[[Function] [Description] [Parameters] " << returns << "]" << std::endl;

    BOOST_FOREACH(function const& f, functions)
    {
        if (f.type == type)
        {
            out << "[[";
            quickbook_synopsis(f, out);
            out << "] [" << f.brief_description << "] [";
            quickbook_short_output(f, out);
            out << "]]" << std::endl;
        }
    }
    out << "]" << std::endl
        << std::endl;
}


void quickbook_output(class_or_struct const& cos, configuration const& config, std::ostream& out)
{
    // Skip namespace
    std::string short_name = namespace_skipped(cos.fullname, config);

    // Write the parsed function
    out << "[section:" << to_section_name(short_name) << " " << short_name << "]" << std::endl
        << std::endl;

    quickbook_output_indexterm(short_name, out);

    out << cos.brief_description << std::endl;
    out << std::endl;

    quickbook_string_with_heading_if_present("Description", cos.detailed_description, out);

    quickbook_markup(cos.qbk_markup, markup_before, markup_synopsis, out);
    out << "[heading Synopsis]" << std::endl
        << "``";
    quickbook_template_parameter_list(cos.template_parameters, out);
    out << (cos.is_class ? "class" : "struct")
        << " " << short_name << std::endl;

    if (! cos.base_classes.empty())
    {
        out << "      : ";
        bool first = true;
        BOOST_FOREACH(base_class const& bc, cos.base_classes)
        {
            if (! first)
            {
                out << std::endl << "      , ";
            }
            out << output_if_different(bc.derivation, "private")
                << output_if_different(bc.virtuality, "non-virtual")
                << namespace_skipped(bc.name, config);
            first = false;
        }
        out << std::endl;
    }

    out << "{" << std::endl
        << "  // ..." << std::endl
        << "};" << std::endl
        << "``" << std::endl << std::endl;
    quickbook_markup(cos.qbk_markup, markup_after, markup_synopsis, out);



    if (! cos.template_parameters.empty())
    {
        bool has_default = false;
        BOOST_FOREACH(parameter const& p, cos.template_parameters)
        {
            if (! p.default_value.empty())
            {
                has_default = true;
            }
        }

        out << "[heading Template parameter(s)]" << std::endl
            << "[table" << std::endl
            << "[[Parameter]";
        if (has_default)
        {
            out << " [Default]";
        }
        out << " [Description]]" << std::endl;

        BOOST_FOREACH(parameter const& p, cos.template_parameters)
        {
            out << "[[" << p.fulltype;
            if (has_default)
            {
                out << "] [" << p.default_value;
            }
            out << "] [" << p.brief_description << "]]" << std::endl;
        }
        out << "]" << std::endl
            << std::endl;
    }


    std::map<function_type, int> counts;
    BOOST_FOREACH(function const& f, cos.functions)
    {
        counts[f.type]++;
    }

    if (counts[function_constructor] > 0)
    {
        quickbook_output_member(cos.functions, function_constructor, "Constructor", config, out);
    }

    if (counts[function_member] > 0)
    {
        quickbook_output_member(cos.functions, function_member, "Member Function", config, out);
    }

    quickbook_header(cos.location, config, out);
    quickbook_markup(cos.qbk_markup, markup_any, markup_default, out);

    out << "[endsect]" << std::endl
        << std::endl;
}


#endif // QUICKBOOK_OUTPUT_HPP
