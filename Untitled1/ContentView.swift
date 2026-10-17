//
//  ContentView.swift
//  Untitled1
//
//  Created by Neel Makhecha on 9/5/25.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Image(systemName: "checkmark.seal.fill")
                .imageScale(.large)
                .foregroundStyle(.tint)
                .font(.title)
                .padding()
            Text("Untitled1 running.")
                .font(.title)
                .padding()
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
