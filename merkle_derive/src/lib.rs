extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;
extern crate merkle;

use proc_macro::TokenStream;

#[proc_macro_derive(Hashable)]
pub fn derive_hashable(input: TokenStream) -> TokenStream {
    let s = input.to_string();
    let ast = syn::parse_derive_input(&s).unwrap();
    let gen = impl_hashable(&ast);
    gen.parse().unwrap()
}

fn impl_hashable(ast: &syn::DeriveInput) -> quote::Tokens {
    let body = match ast.body {
        syn::Body::Struct(ref s) => s,
        _ => panic!("#[derive(Hashable)] is only defined for structs."),
    };

    let stmts: Vec<_> = match *body {
        syn::VariantData::Struct(ref fields) => {
            fields.iter().enumerate().map(hash_field_map).collect()
        }
        syn::VariantData::Tuple(ref fields) => {
            fields.iter().enumerate().map(hash_field_map).collect()
        }
        syn::VariantData::Unit => panic!("#[derive(Hashable)] is not defined for Unit structs."),
    };

    let name = &ast.ident;
    let dummy_const = syn::Ident::new(format!("_IMPL_HASHABLE_FOR_{}", name).to_uppercase());

    quote! {
        const #dummy_const: () = {
            extern crate merkle;

            use std::hash::Hasher;
            use merkle::hash::Hashable;

            impl<H: Hasher> Hashable<H> for #name {
                fn hash(&self, state: &mut H) {
                    #(#stmts)*
                }
            }
        };
    }
}

fn hash_field_map(tuple: (usize, &syn::Field)) -> quote::Tokens {
    hash_field(tuple.0, tuple.1)
}

fn hash_field(index: usize, f: &syn::Field) -> quote::Tokens {
    let mut ty = f.ty.clone();

    loop {
        match ty {
            syn::Ty::Path(_, ref path) => {
                path.segments.first().expect(
                    "there must be at least 1 segment",
                );
                break;
            }
            syn::Ty::Rptr(_, bty) => {
                ty = bty.ty.clone();
            }
            _ => panic!(format!("hashing not supported: {:?}", ty)),
        };
    }

    match f.ident {
        Some(ref ident) => quote! { self.#ident.hash(state); },
        None => quote! { self.#index.hash(state); },
    }
}
