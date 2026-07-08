//
// Copyright © 2025 Daniel Farrelly
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// *	Redistributions of source code must retain the above copyright notice, this list
//		of conditions and the following disclaimer.
// *	Redistributions in binary form must reproduce the above copyright notice, this
//		list of conditions and the following disclaimer in the documentation and/or
//		other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
// OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import SwiftUI
import UniformTypeIdentifiers
import DropboxAuth
import DropboxFiles

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// Browses a single Dropbox folder, demonstrating the full CRUD surface of `DropboxFiles`:
/// live updates via `monitor`, pull-to-refresh via `listFolder`, upload, rename (move), delete,
/// and shared-link creation.
struct FilesView: View {

	@MainActor
	final class ViewModel: ObservableObject {

		let transport: Transport

		let accessToken: AccessToken

		let path: String

		@Published var entries: [any Metadata] = []

		@Published var isLoading = false

		@Published var errorMessage: String?

		@Published var confirmationMessage: String?

		@Published var renamingItem: (any Metadata)?

		@Published var renameText: String = ""

		var monitorTask: Task<Void, Never>?

		/// Deliberately fire-and-forget demo code: each action simply overwrites this without
		/// cancellation or completion tracking — not a managed-lifecycle pattern to copy.
		var actionTask: Task<Void, Never>?

		/// Current entries, keyed by their lowercased path (or name, for entries without one), used
		/// to apply monitor snapshots — both full resets and incremental deltas — without needing to
		/// scan the whole list on every update.
		private var entriesByKey: [String: any Metadata] = [:]

		init(accessToken: AccessToken, path: String) {
			self.transport = Transport(authManager: AuthManager(key: "d25u9w2pgql046o"), token: accessToken)
			self.accessToken = accessToken
			self.path = path
		}

		private func key(for metadata: any Metadata) -> String {
			(metadata.pathLower ?? metadata.name).lowercased()
		}

		// MARK: Listing

		/// Starts the live `monitor` stream for this folder, applying each snapshot as it arrives.
		func startMonitoring() {
			guard monitorTask == nil else { return }

			monitorTask = Task {
				do {
					for try await snapshot in transport.monitor(path: path, isRecursive: false) {
						apply(snapshot)
					}
				}
				catch {
					if Task.isCancelled == false {
						errorMessage = error.localizedDescription
					}
				}
			}
		}

		func stopMonitoring() {
			monitorTask?.cancel()
			monitorTask = nil
		}

		/// Applies a `Snapshot` from either `monitor` or a one-shot `listFolder` refresh.
		///
		/// A reset snapshot (`isReset == true`) is the complete folder state, so it replaces the local
		/// entries outright. A delta snapshot only carries what changed since the previous cursor: entries
		/// that are still present are upserted, and entries reported as `DeletedMetadata` are removed.
		func apply(_ snapshot: Snapshot) {
			if snapshot.isReset {
				entriesByKey = Dictionary(
					uniqueKeysWithValues: snapshot.metadata.map { (key(for: $0), $0) }
				)
			}
			else {
				for item in snapshot.metadata {
					if item is DeletedMetadata {
						entriesByKey.removeValue(forKey: key(for: item))
					}
					else {
						entriesByKey[key(for: item)] = item
					}
				}
			}

			entries = entriesByKey.values.sorted { lhs, rhs in
				if (lhs is FolderMetadata) != (rhs is FolderMetadata) {
					return lhs is FolderMetadata
				}
				return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
			}
		}

		/// One-shot refresh, used for pull-to-refresh. Always yields a complete (reset) snapshot.
		func refresh() async {
			isLoading = true
			defer { isLoading = false }

			do {
				apply(try await transport.listFolder(at: path, isRecursive: false))
			}
			catch {
				errorMessage = error.localizedDescription
			}
		}

		// MARK: Upload

		/// Uploads the file at `url` into the current folder, using the construct-then-parse flow:
		/// a signed `URLRequest` is built via `Transport.urlRequest(for:)`, executed with a plain
		/// `URLSession`, and the result parsed via the request's own `response(from:httpResponse:)`.
		func upload(_ url: URL) async {
			do {
				guard url.startAccessingSecurityScopedResource() else {
					throw CocoaError(.fileReadNoPermission)
				}
				defer { url.stopAccessingSecurityScopedResource() }

				let contents = try Data(contentsOf: url)
				let destination = (path.isEmpty ? "/" : path + "/") + url.lastPathComponent

				let request = Upload.Request(path: destination, mode: .add, autorename: true, contents: contents)
				let urlRequest = try await transport.urlRequest(for: request)
				let (data, response) = try await URLSession.shared.data(for: urlRequest)

				guard let httpResponse = response as? HTTPURLResponse else {
					throw URLError(.badServerResponse)
				}

				_ = try request.response(from: data, httpResponse: httpResponse)
			}
			catch {
				errorMessage = error.localizedDescription
			}
		}

		// MARK: Rename

		func beginRename(_ metadata: any Metadata) {
			renamingItem = metadata
			renameText = metadata.name
		}

		/// Renames `metadata` to `newName` in place, via `move(from:to:autorename:)`.
		///
		/// The item and name are passed in (captured when the user confirms) rather than read from
		/// `renamingItem`/`renameText`, since dismissing the rename sheet clears that state before
		/// this async work runs.
		func confirmRename(_ metadata: any Metadata, newName: String) async {
			guard let fromPath = metadata.pathLower else { return }

			guard newName.isEmpty == false, newName != metadata.name else { return }

			do {
				_ = try await transport.move(from: fromPath, to: renamedPath(for: metadata, newName: newName), autorename: true)
			}
			catch {
				errorMessage = error.localizedDescription
			}
		}

		private func renamedPath(for metadata: any Metadata, newName: String) -> String {
			// Prefer `pathDisplay` for the parent components, since it preserves canonical casing.
			let path = metadata.pathDisplay ?? metadata.pathLower ?? ""
			var components = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
			if components.isEmpty == false {
				components.removeLast()
			}
			components.append(newName)
			return "/" + components.joined(separator: "/")
		}

		// MARK: Delete

		func delete(_ metadata: any Metadata) async {
			guard let path = metadata.pathLower else { return }

			do {
				_ = try await transport.delete(path: path)
				entriesByKey.removeValue(forKey: key(for: metadata))
				entries.removeAll { key(for: $0) == key(for: metadata) }
			}
			catch {
				errorMessage = error.localizedDescription
			}
		}

		// MARK: Share link

		/// Creates a shared link for `metadata`, copies its URL to the pasteboard, and confirms.
		///
		/// If the link already exists, Dropbox reports `sharedLinkAlreadyExists` — and the package
		/// decodes the existing link's metadata directly from that error when the API includes it, so
		/// this reuses it rather than making a follow-up `ListSharedLinks` request.
		func shareLink(for metadata: any Metadata) async {
			guard let path = metadata.pathLower else { return }

			do {
				let link = try await transport.createSharedLinkWithSettings(path: path)
				copyToPasteboard(link.url.absoluteString)
				confirmationMessage = "Copied share link for “\(metadata.name)” to the clipboard."
			}
			catch CreateSharedLinkWithSettings.Error.sharedLinkAlreadyExists(let existingLink) {
				guard let existingLink else {
					errorMessage = "A shared link already exists for “\(metadata.name)”, but its URL couldn't be recovered."
					return
				}
				copyToPasteboard(existingLink.url.absoluteString)
				confirmationMessage = "Copied existing share link for “\(metadata.name)” to the clipboard."
			}
			catch {
				errorMessage = error.localizedDescription
			}
		}

		private func copyToPasteboard(_ string: String) {
			#if canImport(UIKit)
			UIPasteboard.general.string = string
			#elseif canImport(AppKit)
			NSPasteboard.general.clearContents()
			NSPasteboard.general.setString(string, forType: .string)
			#endif
		}

	}

	/// `@StateObject` (rather than the `@ObservedObject` used elsewhere in this app) because this
	/// view model owns a live monitor stream: recreating it on every view re-init would orphan the
	/// running `monitorTask` and reset accumulated state.
	@StateObject private var viewModel: ViewModel

	@State private var isShowingImporter = false

	init(accessToken: AccessToken, path: String = "") {
		self._viewModel = StateObject(wrappedValue: ViewModel(accessToken: accessToken, path: path))
	}

	var body: some View {
		List {
			ForEach(viewModel.entries, id: \.name) { metadata in
				row(for: metadata)
			}
		}
		.navigationTitle(title)
		.toolbar {
			ToolbarItem {
				Button {
					isShowingImporter = true
				} label: {
					Label("Upload", systemImage: "square.and.arrow.up")
				}
			}
		}
		.refreshable {
			await viewModel.refresh()
		}
		.task {
			viewModel.startMonitoring()
		}
		.onDisappear {
			viewModel.stopMonitoring()
		}
		.fileImporter(isPresented: $isShowingImporter, allowedContentTypes: [.image]) { result in
			switch result {
			case .success(let url):
				viewModel.actionTask = Task { await viewModel.upload(url) }
			case .failure(let error):
				viewModel.errorMessage = error.localizedDescription
			}
		}
		// A sheet rather than an alert, since `TextField` inside `.alert` requires
		// iOS 16/macOS 13, and this app targets iOS 15/macOS 12.3.
		.sheet(
			isPresented: Binding(
				get: { viewModel.renamingItem != nil },
				set: { isPresented in if isPresented == false { viewModel.renamingItem = nil } }
			)
		) {
			renameSheet
		}
		.alert(
			"Error",
			isPresented: Binding(
				get: { viewModel.errorMessage != nil },
				set: { isPresented in if isPresented == false { viewModel.errorMessage = nil } }
			)
		) {
			Button("OK", role: .cancel) {}
		} message: {
			Text(viewModel.errorMessage ?? "")
		}
		.alert(
			"Shared Link",
			isPresented: Binding(
				get: { viewModel.confirmationMessage != nil },
				set: { isPresented in if isPresented == false { viewModel.confirmationMessage = nil } }
			)
		) {
			Button("OK", role: .cancel) {}
		} message: {
			Text(viewModel.confirmationMessage ?? "")
		}
	}

	@ViewBuilder
	private var renameSheet: some View {
		VStack(spacing: 16) {
			Text("Rename")
				.font(.headline)

			TextField("Name", text: $viewModel.renameText)
				.textFieldStyle(.roundedBorder)

			HStack {
				Button("Cancel", role: .cancel) {
					viewModel.renamingItem = nil
				}

				Spacer()

				Button("Rename") {
					// Capture the item and name now: dismissing the sheet clears
					// `renamingItem` before the async task gets a chance to run.
					if let metadata = viewModel.renamingItem {
						let newName = viewModel.renameText
						viewModel.actionTask = Task { await viewModel.confirmRename(metadata, newName: newName) }
					}
					viewModel.renamingItem = nil
				}
				.keyboardShortcut(.defaultAction)
			}
		}
		.padding()
		.frame(minWidth: 300)
	}

	private var title: String {
		guard viewModel.path.isEmpty == false, let name = viewModel.path.split(separator: "/").last else {
			return "Files"
		}
		return String(name)
	}

	@ViewBuilder
	private func row(for metadata: any Metadata) -> some View {
		let content = HStack {
			FileThumbnailView(transport: viewModel.transport, metadata: metadata)
				.frame(width: 40, height: 40)

			VStack(alignment: .leading) {
				Text(metadata.name)

				if let file = metadata as? FileMetadata {
					Text("\(ByteCountFormatter.string(fromByteCount: file.numberOfBytes, countStyle: .file)) • \(file.dateModifiedOnServer.formatted(date: .abbreviated, time: .shortened))")
						.font(.caption)
						.foregroundStyle(.secondary)
				}
			}
		}

		if metadata is FolderMetadata, let path = metadata.pathLower {
			NavigationLink(destination: FilesView(accessToken: viewModel.accessToken, path: path)) {
				content
			}
			.swipeActions(edge: .trailing) {
				deleteButton(for: metadata)
			}
			.contextMenu {
				renameButton(for: metadata)
				shareLinkButton(for: metadata)
				deleteButton(for: metadata)
			}
		}
		else {
			content
				.swipeActions(edge: .trailing) {
					deleteButton(for: metadata)
				}
				.contextMenu {
					renameButton(for: metadata)
					shareLinkButton(for: metadata)
					deleteButton(for: metadata)
				}
		}
	}

	private func renameButton(for metadata: any Metadata) -> some View {
		Button {
			viewModel.beginRename(metadata)
		} label: {
			Label("Rename", systemImage: "pencil")
		}
	}

	private func shareLinkButton(for metadata: any Metadata) -> some View {
		Button {
			viewModel.actionTask = Task { await viewModel.shareLink(for: metadata) }
		} label: {
			Label("Copy Share Link", systemImage: "link")
		}
	}

	private func deleteButton(for metadata: any Metadata) -> some View {
		Button(role: .destructive) {
			viewModel.actionTask = Task { await viewModel.delete(metadata) }
		} label: {
			Label("Delete", systemImage: "trash")
		}
	}

}
