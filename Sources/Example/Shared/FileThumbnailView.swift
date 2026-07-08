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
import DropboxAuth
import DropboxFiles

/// A row thumbnail for a folder entry: a fetched image for image-like files, a placeholder icon
/// otherwise (including while the thumbnail is still loading).
struct FileThumbnailView: View {

	let transport: Transport

	let metadata: any Metadata

	@State private var image: PlatformImage?

	var body: some View {
		Group {
			if let image {
				Image(platformImage: image)
					.resizable()
					.aspectRatio(contentMode: .fill)
					.clipShape(RoundedRectangle(cornerRadius: 4))
			}
			else {
				Image(systemName: metadata is FolderMetadata ? "folder.fill" : "doc.fill")
					.foregroundStyle(.secondary)
			}
		}
		// Keyed by the cache key (path + revision) so the thumbnail refetches when the file's
		// contents change (a new revision), not only when the row shows a different path.
		.task(id: cacheKey) {
			await loadThumbnailIfNeeded()
		}
	}

	private var cacheKey: String? {
		guard
			let file = metadata as? FileMetadata,
			let path = file.pathLower,
			file.isImageLike
		else {
			return nil
		}

		return path + "#" + file.revision.rawValue
	}

	private func loadThumbnailIfNeeded() async {
		guard
			let cacheKey,
			let file = metadata as? FileMetadata,
			let path = file.pathLower
		else {
			return
		}

		if let cached = await ThumbnailCache.shared.data(for: cacheKey) {
			image = PlatformImage(data: cached)
			return
		}

		// Thumbnails are best-effort: unsupported files routinely fail here (wrong extension,
		// conversion error, etc.), which is expected rather than exceptional — so failures fall
		// back to the placeholder icon rather than surfacing a per-row error alert.
		do {
			let request = GetThumbnail.Request(path: path)
			let urlRequest = try await transport.urlRequest(for: request)
			let (data, response) = try await URLSession.shared.data(for: urlRequest)

			guard let httpResponse = response as? HTTPURLResponse else { return }

			_ = try request.response(from: data, httpResponse: httpResponse)

			await ThumbnailCache.shared.store(data, for: cacheKey)
			image = PlatformImage(data: data)
		}
		catch {
			// Fall back to the placeholder icon; see comment above.
		}
	}

}

extension FileMetadata {

	/// Whether this file's extension suggests `GetThumbnail` can produce a preview for it.
	var isImageLike: Bool {
		let imageExtensions: Set<String> = ["jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "heic", "webp"]
		return imageExtensions.contains((name as NSString).pathExtension.lowercased())
	}

}

extension Image {

	init(platformImage: PlatformImage) {
		#if canImport(UIKit)
		self.init(uiImage: platformImage)
		#elseif canImport(AppKit)
		self.init(nsImage: platformImage)
		#endif
	}

}
