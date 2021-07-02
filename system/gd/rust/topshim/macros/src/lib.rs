//! Macro for topshim

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream, Result};
use syn::{parse_macro_input, Block, Ident, Path, Stmt, Token, Type};

/// Parsed structure for callback variant
struct CbVariant {
    dispatcher: Type,
    fn_pair: (Ident, Path),
    arg_pairs: Vec<(Type, Type)>,
    stmts: Vec<Stmt>,
}

impl Parse for CbVariant {
    fn parse(input: ParseStream) -> Result<Self> {
        // First thing should be the dispatcher
        let dispatcher: Type = input.parse()?;
        input.parse::<Token![,]>()?;

        // Name and return type are parsed
        let name: Ident = input.parse()?;
        input.parse::<Token![->]>()?;
        let rpath: Path = input.parse()?;

        let mut arg_pairs: Vec<(Type, Type)> = Vec::new();
        let mut stmts: Vec<Stmt> = Vec::new();

        while input.peek(Token![,]) {
            // Discard the comma
            input.parse::<Token![,]>()?;

            // Check if we're expecting the final Block
            if input.peek(syn::token::Brace) {
                let block: Block = input.parse()?;
                stmts.extend(block.stmts);

                break;
            }

            // Grab the next type argument
            let start_type: Type = input.parse()?;

            if input.peek(Token![->]) {
                // Discard ->
                input.parse::<Token![->]>()?;

                let end_type: Type = input.parse()?;

                arg_pairs.push((start_type, end_type))
            } else {
                arg_pairs.push((start_type.clone(), start_type));
            }
        }

        // TODO: Validate there are no more tokens; currently they are ignored.
        Ok(CbVariant { dispatcher, fn_pair: (name, rpath), arg_pairs, stmts })
    }
}

#[proc_macro]
/// Implement C function to convert callback into enum variant.
///
/// Expected syntax:
///     cb_variant(DispatcherType, function_name -> EnumType::Variant, args..., {
///         // Statements (maybe converting types)
///         // Args in order will be _0, _1, etc.
///     })
pub fn cb_variant(input: TokenStream) -> TokenStream {
    let parsed_cptr = parse_macro_input!(input as CbVariant);

    let dispatcher = parsed_cptr.dispatcher;
    let (ident, rpath) = parsed_cptr.fn_pair;

    let mut params = proc_macro2::TokenStream::new();
    let mut args = proc_macro2::TokenStream::new();
    for (i, (start, end)) in parsed_cptr.arg_pairs.iter().enumerate() {
        let ident = format_ident!("_{}", i);
        params.extend(quote! { #ident: #start, });

        // Argument needs an into translation if it doesn't match the start
        if start != end {
            args.extend(quote! { #end::from(#ident), });
        } else {
            args.extend(quote! {#ident,});
        }
    }

    let mut stmts = proc_macro2::TokenStream::new();
    for stmt in parsed_cptr.stmts {
        stmts.extend(quote! { #stmt });
    }

    let tokens = quote! {
        #[no_mangle]
        extern "C" fn #ident(#params) {
            #stmts

            unsafe {
                (get_dispatchers().lock().unwrap().get::<#dispatcher>().unwrap().clone().lock().unwrap().dispatch)(#rpath(#args));
            }
        }
    };

    TokenStream::from(tokens)
}
