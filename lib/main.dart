import 'dart:convert';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart' as aes_lib;
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const GoogleBooksApp());
}

class GoogleBooksApp extends StatelessWidget {
  const GoogleBooksApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Google Books Importer',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: Colors.blue,
      ),
      home: const GoogleBooksPage(),
    );
  }
}

class ApiConfig {
  static const String serverSaveUrl =
      'https://api.dimas-server.my.id/save.php';

  static const String serverListUrl =
      'https://api.dimas-server.my.id/list_books.php';

  // Google Books API publik bisa dipakai tanpa API key untuk percobaan sederhana.
  // Jika punya API key, isi di sini.
  static const String googleBooksApiKey =
      'AIzaSyANRDaGkJz7wDgDBSd-YpvLX_vM9TVFZTc';
}

// ---------------------------------------------------------------------------
// InfinityFreeHttpClient
// Menangani anti-bot challenge AES dari InfinityFree secara otomatis.
// Cara kerja:
//   1. Request pertama – server kembalikan halaman HTML berisi JS challenge.
//   2. Parsing hex key, IV, ciphertext dari HTML tersebut.
//   3. Decrypt dengan AES-CBC (mode 2 = CBC di slowAES).
//   4. Kirim ulang request dengan cookie __test=<hasil decrypt> ke URL ?i=1.
// ---------------------------------------------------------------------------
class InfinityFreeHttpClient {
  // Cookie __test disimpan agar tidak perlu solve ulang tiap request.
  static String? _cachedCookie;

  static final RegExp _aRegex =
      RegExp(r'var a=toNumbers\("([a-f0-9]+)"\)');
  static final RegExp _bRegex =
      RegExp(r'var b=toNumbers\("([a-f0-9]+)"\)');
  static final RegExp _cRegex =
      RegExp(r'var c=toNumbers\("([a-f0-9]+)"\)');

  // Konversi hex string ke Uint8List
  static Uint8List _hexToBytes(String hex) {
    final result = Uint8List(hex.length ~/ 2);
    for (int i = 0; i < result.length; i++) {
      result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return result;
  }

  // Konversi Uint8List ke hex string lowercase
  static String _bytesToHex(List<int> bytes) {
    return bytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  // Cek apakah respons adalah challenge InfinityFree
  static bool _isChallenge(http.Response response) {
    return response.body.contains('slowAES.decrypt') &&
        response.body.contains('__test');
  }

  // Selesaikan challenge AES dan kembalikan nilai cookie __test
  static String? _solveChallenge(String html) {
    final aMatch = _aRegex.firstMatch(html);
    final bMatch = _bRegex.firstMatch(html);
    final cMatch = _cRegex.firstMatch(html);

    if (aMatch == null || bMatch == null || cMatch == null) return null;

    final keyHex = aMatch.group(1)!;
    final ivHex = bMatch.group(1)!;
    final ciphertextHex = cMatch.group(1)!;

    try {
      final key = aes_lib.Key(_hexToBytes(keyHex));
      final iv = aes_lib.IV(_hexToBytes(ivHex));
      final encrypter = aes_lib.Encrypter(
        aes_lib.AES(key, mode: aes_lib.AESMode.cbc, padding: null),
      );
      final encrypted = aes_lib.Encrypted(_hexToBytes(ciphertextHex));
      final decryptedBytes = encrypter.decryptBytes(encrypted, iv: iv);
      return _bytesToHex(decryptedBytes);
    } catch (e) {
      return null;
    }
  }

  // Buat Map header dengan cookie yang sudah di-solve
  static Map<String, String> _headersWithCookie(
      Map<String, String>? existing, String cookie) {
    final headers = Map<String, String>.from(existing ?? {});
    headers['Cookie'] = '__test=$cookie';
    return headers;
  }

  // URL setelah redirect challenge (server arahkan ke ?i=1)
  static String _redirectUrl(String originalUrl) {
    return originalUrl.contains('?')
        ? '$originalUrl&i=1'
        : '$originalUrl?i=1';
  }

  // GET request dengan bypass challenge otomatis
  static Future<http.Response> get(
    String url, {
    Map<String, String>? headers,
  }) async {
    // Gunakan cookie cache jika sudah ada
    if (_cachedCookie != null) {
      final cachedHeaders = _headersWithCookie(headers, _cachedCookie!);
      final response = await http.get(
        Uri.parse(_redirectUrl(url)),
        headers: cachedHeaders,
      );
      if (!_isChallenge(response)) return response;
      // Cookie expired, reset cache
      _cachedCookie = null;
    }

    // Request pertama – ambil challenge
    final initialResponse = await http.get(Uri.parse(url), headers: headers);

    if (!_isChallenge(initialResponse)) return initialResponse;

    final cookie = _solveChallenge(initialResponse.body);
    if (cookie == null) return initialResponse;

    _cachedCookie = cookie;

    // Request ulang dengan cookie
    final newHeaders = _headersWithCookie(headers, cookie);
    return http.get(Uri.parse(_redirectUrl(url)), headers: newHeaders);
  }

  // POST request dengan bypass challenge otomatis
  static Future<http.Response> post(
    String url, {
    Map<String, String>? headers,
    String? body,
  }) async {
    // Gunakan cookie cache jika sudah ada
    if (_cachedCookie != null) {
      final cachedHeaders = _headersWithCookie(headers, _cachedCookie!);
      final response = await http.post(
        Uri.parse(_redirectUrl(url)),
        headers: cachedHeaders,
        body: body,
      );
      if (!_isChallenge(response)) return response;
      _cachedCookie = null;
    }

    // GET dulu untuk ambil challenge (server kasih challenge di GET)
    final challengeResponse = await http.get(Uri.parse(url));

    if (_isChallenge(challengeResponse)) {
      final cookie = _solveChallenge(challengeResponse.body);
      if (cookie != null) {
        _cachedCookie = cookie;
      }
    }

    final newHeaders = _cachedCookie != null
        ? _headersWithCookie(headers, _cachedCookie!)
        : (headers ?? {});

    return http.post(
      Uri.parse(_redirectUrl(url)),
      headers: newHeaders,
      body: body,
    );
  }
}

class BookModel {
  final String googleVolumeId;
  final String title;
  final String? subtitle;
  final List<String> authors;
  final String? publisher;
  final String? publishedDate;
  final String? description;
  final int? pageCount;
  final String? language;
  final String? thumbnail;
  final String? previewLink;
  final String? infoLink;
  final double? averageRating;
  final int? ratingsCount;
  final String? maturityRating;
  final List<String> categories;
  final List<Map<String, dynamic>> identifiers;
  final Map<String, dynamic> rawJson;

  BookModel({
    required this.googleVolumeId,
    required this.title,
    this.subtitle,
    required this.authors,
    this.publisher,
    this.publishedDate,
    this.description,
    this.pageCount,
    this.language,
    this.thumbnail,
    this.previewLink,
    this.infoLink,
    this.averageRating,
    this.ratingsCount,
    this.maturityRating,
    required this.categories,
    required this.identifiers,
    required this.rawJson,
  });

  factory BookModel.fromGoogleBooksJson(Map<String, dynamic> item) {
    final Map<String, dynamic> volumeInfo =
        item['volumeInfo'] is Map<String, dynamic>
            ? item['volumeInfo'] as Map<String, dynamic>
            : <String, dynamic>{};

    final dynamic authorsRaw = volumeInfo['authors'];
    final dynamic categoriesRaw = volumeInfo['categories'];
    final dynamic identifiersRaw = volumeInfo['industryIdentifiers'];

    String? thumbnail;

    if (volumeInfo['imageLinks'] is Map<String, dynamic>) {
      final imageLinks = volumeInfo['imageLinks'] as Map<String, dynamic>;
      thumbnail = imageLinks['thumbnail']?.toString();
    }

    return BookModel(
      googleVolumeId: item['id']?.toString() ?? '',
      title: volumeInfo['title']?.toString() ?? 'Tanpa Judul',
      subtitle: volumeInfo['subtitle']?.toString(),
      authors: authorsRaw is List
          ? authorsRaw.map((author) => author.toString()).toList()
          : <String>[],
      publisher: volumeInfo['publisher']?.toString(),
      publishedDate: volumeInfo['publishedDate']?.toString(),
      description: volumeInfo['description']?.toString(),
      pageCount: parseInt(volumeInfo['pageCount']),
      language: volumeInfo['language']?.toString(),
      thumbnail: thumbnail,
      previewLink: volumeInfo['previewLink']?.toString(),
      infoLink: volumeInfo['infoLink']?.toString(),
      averageRating: parseDouble(volumeInfo['averageRating']),
      ratingsCount: parseInt(volumeInfo['ratingsCount']),
      maturityRating: volumeInfo['maturityRating']?.toString(),
      categories: categoriesRaw is List
          ? categoriesRaw.map((category) => category.toString()).toList()
          : <String>[],
      identifiers: identifiersRaw is List
          ? identifiersRaw
              .whereType<Map>()
              .map((item) => Map<String, dynamic>.from(item))
              .toList()
          : <Map<String, dynamic>>[],
      rawJson: item,
    );
  }

  factory BookModel.fromServerJson(Map<String, dynamic> item) {
    return BookModel(
      googleVolumeId: item['google_volume_id']?.toString() ?? '',
      title: item['title']?.toString() ?? 'Tanpa Judul',
      subtitle: item['subtitle']?.toString(),
      authors: <String>[],
      publisher: item['publisher']?.toString(),
      publishedDate: item['published_date']?.toString(),
      description: item['description']?.toString(),
      pageCount: parseInt(item['page_count']),
      language: item['language']?.toString(),
      thumbnail: item['thumbnail']?.toString(),
      previewLink: item['preview_link']?.toString(),
      infoLink: item['info_link']?.toString(),
      averageRating: parseDouble(item['average_rating']),
      ratingsCount: parseInt(item['ratings_count']),
      maturityRating: item['maturity_rating']?.toString(),
      categories: <String>[],
      identifiers: <Map<String, dynamic>>[],
      rawJson: item,
    );
  }

  Map<String, dynamic> toServerJson() {
    return {
      'google_volume_id': googleVolumeId,
      'title': title,
      'subtitle': subtitle,
      'authors': authors,
      'publisher': publisher,
      'published_date': publishedDate,
      'description': description,
      'page_count': pageCount,
      'language': language,
      'thumbnail': thumbnail,
      'preview_link': previewLink,
      'info_link': infoLink,
      'average_rating': averageRating,
      'ratings_count': ratingsCount,
      'maturity_rating': maturityRating,
      'categories': categories,
      'identifiers': identifiers,
      'raw_json': rawJson,
    };
  }

  static int? parseInt(dynamic value) {
    if (value == null) return null;
    if (value is int) return value;
    if (value is num) return value.toInt();
    return int.tryParse(value.toString());
  }

  static double? parseDouble(dynamic value) {
    if (value == null) return null;
    if (value is double) return value;
    if (value is num) return value.toDouble();
    return double.tryParse(value.toString());
  }
}

class GoogleBooksPage extends StatefulWidget {
  const GoogleBooksPage({super.key});

  @override
  State<GoogleBooksPage> createState() => _GoogleBooksPageState();
}

class _GoogleBooksPageState extends State<GoogleBooksPage> {
  final TextEditingController searchController = TextEditingController();

  List<BookModel> books = [];
  List<BookModel> savedBooks = [];

  Set<String> selectedBookIds = {};

  bool isLoadingGoogleBooks = false;
  bool isSavingBooks = false;
  bool isLoadingSavedBooks = false;

  int maxResults = 10;
  String selectedLanguage = '';

  @override
  void initState() {
    super.initState();
    loadSavedBooks();
  }

  Future<Map<String, dynamic>> decodeJsonResponse(
      http.Response response) async {
    try {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } catch (_) {
      throw Exception(
        'Response server bukan JSON valid. '
        'Status: ${response.statusCode}. '
        'Isi response: ${response.body.substring(0, response.body.length > 200 ? 200 : response.body.length)}',
      );
    }
  }

  Future<void> searchBooksFromGoogle() async {
    final String query = searchController.text.trim();

    if (query.isEmpty) {
      showMessage('Masukkan kata kunci pencarian buku.');
      return;
    }

    setState(() {
      isLoadingGoogleBooks = true;
      books = [];
      selectedBookIds = {};
    });

    try {
      final Map<String, String> queryParams = {
        'q': query,
        'maxResults': maxResults.toString(),
        'startIndex': '0',
      };

      if (selectedLanguage.isNotEmpty) {
        queryParams['langRestrict'] = selectedLanguage;
      }

      if (ApiConfig.googleBooksApiKey.isNotEmpty) {
        queryParams['key'] = ApiConfig.googleBooksApiKey;
      }

      final Uri uri = Uri.https(
        'www.googleapis.com',
        '/books/v1/volumes',
        queryParams,
      );

      final http.Response response = await http.get(uri);

      if (response.statusCode != 200) {
        throw Exception(
          'Gagal mengambil data dari Google Books API. '
          'Status code: ${response.statusCode}',
        );
      }

      final Map<String, dynamic> decoded =
          jsonDecode(response.body) as Map<String, dynamic>;

      final dynamic items = decoded['items'];

      if (items == null || items is! List || items.isEmpty) {
        showMessage('Data buku tidak ditemukan.');
        return;
      }

      final List<BookModel> result = items
          .whereType<Map<String, dynamic>>()
          .map(BookModel.fromGoogleBooksJson)
          .where((book) => book.googleVolumeId.isNotEmpty)
          .toList();

      setState(() {
        books = result;
        selectedBookIds = result.map((book) => book.googleVolumeId).toSet();
      });

      showMessage('${result.length} buku berhasil diambil dari Google Books.');
    } catch (e) {
      showMessage('Error mengambil data: $e');
    } finally {
      setState(() {
        isLoadingGoogleBooks = false;
      });
    }
  }

  Future<void> saveSelectedBooksToInfinityFree() async {
    final List<BookModel> selectedBooks = books
        .where((book) => selectedBookIds.contains(book.googleVolumeId))
        .toList();

    if (selectedBooks.isEmpty) {
      showMessage('Pilih minimal satu buku untuk disimpan.');
      return;
    }

    setState(() {
      isSavingBooks = true;
    });

    try {
      final http.Response response = await InfinityFreeHttpClient.post(
        ApiConfig.serverSaveUrl,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Accept': 'application/json',
        },
        body: jsonEncode({
          'books': selectedBooks.map((book) => book.toServerJson()).toList(),
        }),
      );

      final Map<String, dynamic> decoded = await decodeJsonResponse(response);

      if (response.statusCode != 200 || decoded['success'] != true) {
        throw Exception(decoded['message'] ?? 'Gagal menyimpan data.');
      }

      final dynamic savedCount = decoded['data']?['saved_count'];

      showMessage(
        'Berhasil menyimpan ${savedCount ?? selectedBooks.length} buku ke database.',
      );

      await loadSavedBooks();
    } catch (e) {
      showMessage('Error menyimpan data: $e');
    } finally {
      setState(() {
        isSavingBooks = false;
      });
    }
  }

  Future<void> loadSavedBooks() async {
    setState(() {
      isLoadingSavedBooks = true;
    });

    try {
      final http.Response response = await InfinityFreeHttpClient.get(
        ApiConfig.serverListUrl,
        headers: {
          'Accept': 'application/json',
        },
      );

      final Map<String, dynamic> decoded = await decodeJsonResponse(response);

      if (response.statusCode != 200 || decoded['success'] != true) {
        throw Exception(
            decoded['message'] ?? 'Gagal mengambil data tersimpan.');
      }

      final dynamic data = decoded['data'];

      if (data is List) {
        setState(() {
          savedBooks = data
              .whereType<Map<String, dynamic>>()
              .map(BookModel.fromServerJson)
              .toList();
        });
      }
    } catch (e) {
      showMessage('Error mengambil data tersimpan: $e');
    } finally {
      setState(() {
        isLoadingSavedBooks = false;
      });
    }
  }

  void toggleBookSelection(BookModel book, bool? value) {
    setState(() {
      if (value == true) {
        selectedBookIds.add(book.googleVolumeId);
      } else {
        selectedBookIds.remove(book.googleVolumeId);
      }
    });
  }

  void selectAllBooks() {
    setState(() {
      selectedBookIds = books.map((book) => book.googleVolumeId).toSet();
    });
  }

  void unselectAllBooks() {
    setState(() {
      selectedBookIds.clear();
    });
  }

  void showMessage(String message) {
    if (!mounted) return;

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        duration: const Duration(seconds: 4),
      ),
    );
  }

  @override
  void dispose() {
    searchController.dispose();
    super.dispose();
  }

  Widget buildSearchForm() {
    return Card(
      elevation: 1,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            TextField(
              controller: searchController,
              decoration: const InputDecoration(
                labelText: 'Kata kunci buku',
                hintText: 'Contoh: database, flutter, artificial intelligence',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.search),
              ),
              onSubmitted: (_) => searchBooksFromGoogle(),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: DropdownButtonFormField<int>(
                    initialValue: maxResults,
                    decoration: const InputDecoration(
                      labelText: 'Jumlah data',
                      border: OutlineInputBorder(),
                    ),
                    items: const [
                      DropdownMenuItem(
                        value: 10,
                        child: Text('10 Buku'),
                      ),
                      DropdownMenuItem(
                        value: 20,
                        child: Text('20 Buku'),
                      ),
                      DropdownMenuItem(
                        value: 30,
                        child: Text('30 Buku'),
                      ),
                      DropdownMenuItem(
                        value: 40,
                        child: Text('40 Buku'),
                      ),
                    ],
                    onChanged: (value) {
                      if (value != null) {
                        setState(() {
                          maxResults = value;
                        });
                      }
                    },
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: DropdownButtonFormField<String>(
                    initialValue: selectedLanguage,
                    decoration: const InputDecoration(
                      labelText: 'Bahasa',
                      border: OutlineInputBorder(),
                    ),
                    items: const [
                      DropdownMenuItem(
                        value: '',
                        child: Text('Semua'),
                      ),
                      DropdownMenuItem(
                        value: 'id',
                        child: Text('Indonesia'),
                      ),
                      DropdownMenuItem(
                        value: 'en',
                        child: Text('English'),
                      ),
                    ],
                    onChanged: (value) {
                      setState(() {
                        selectedLanguage = value ?? '';
                      });
                    },
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: isLoadingGoogleBooks ? null : searchBooksFromGoogle,
                icon: const Icon(Icons.search),
                label: Text(
                  isLoadingGoogleBooks
                      ? 'Mengambil data...'
                      : 'Cari Buku dari Google Books',
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget buildActionButtons() {
    if (books.isEmpty) {
      return const SizedBox.shrink();
    }

    return Card(
      elevation: 1,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Wrap(
          spacing: 8,
          runSpacing: 8,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            Text(
              'Dipilih: ${selectedBookIds.length} dari ${books.length}',
              style: const TextStyle(
                fontWeight: FontWeight.bold,
              ),
            ),
            OutlinedButton.icon(
              onPressed: selectAllBooks,
              icon: const Icon(Icons.check_box),
              label: const Text('Pilih Semua'),
            ),
            OutlinedButton.icon(
              onPressed: unselectAllBooks,
              icon: const Icon(Icons.check_box_outline_blank),
              label: const Text('Hapus Pilihan'),
            ),
            FilledButton.icon(
              onPressed: isSavingBooks ? null : saveSelectedBooksToInfinityFree,
              icon: const Icon(Icons.cloud_upload),
              label: Text(
                isSavingBooks ? 'Menyimpan...' : 'Simpan ke Database',
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget buildBookCard(BookModel book) {
    final bool isSelected = selectedBookIds.contains(book.googleVolumeId);

    return Card(
      elevation: 1,
      margin: const EdgeInsets.only(bottom: 10),
      child: CheckboxListTile(
        value: isSelected,
        onChanged: (value) => toggleBookSelection(book, value),
        controlAffinity: ListTileControlAffinity.trailing,
        title: Text(
          book.title,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: const TextStyle(
            fontWeight: FontWeight.bold,
          ),
        ),
        subtitle: Padding(
          padding: const EdgeInsets.only(top: 6),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              buildThumbnail(book.thumbnail),
              const SizedBox(width: 10),
              Expanded(
                child: buildBookInfo(book),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget buildThumbnail(String? thumbnail) {
    if (thumbnail == null || thumbnail.isEmpty) {
      return Container(
        width: 55,
        height: 75,
        alignment: Alignment.center,
        color: Colors.grey.shade200,
        child: const Icon(Icons.menu_book),
      );
    }

    final String imageUrl = thumbnail.replaceFirst('http://', 'https://');

    return Image.network(
      imageUrl,
      width: 55,
      height: 75,
      fit: BoxFit.cover,
      errorBuilder: (context, error, stackTrace) {
        return Container(
          width: 55,
          height: 75,
          alignment: Alignment.center,
          color: Colors.grey.shade200,
          child: const Icon(Icons.broken_image),
        );
      },
    );
  }

  Widget buildBookInfo(BookModel book) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          book.authors.isEmpty
              ? 'Penulis: -'
              : 'Penulis: ${book.authors.join(', ')}',
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
        ),
        Text('Penerbit: ${book.publisher ?? '-'}'),
        Text('Tanggal terbit: ${book.publishedDate ?? '-'}'),
        Text('Jumlah halaman: ${book.pageCount?.toString() ?? '-'}'),
        Text('Bahasa: ${book.language ?? '-'}'),
        if (book.categories.isNotEmpty)
          Text(
            'Kategori: ${book.categories.join(', ')}',
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
      ],
    );
  }

  Widget buildGoogleBooksResult() {
    if (isLoadingGoogleBooks) {
      return const Padding(
        padding: EdgeInsets.all(32),
        child: Center(
          child: CircularProgressIndicator(),
        ),
      );
    }

    if (books.isEmpty) {
      return const Card(
        elevation: 1,
        child: Padding(
          padding: EdgeInsets.all(24),
          child: Center(
            child: Text(
              'Belum ada hasil pencarian. Silakan cari buku terlebih dahulu.',
            ),
          ),
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Hasil Pencarian Google Books',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        ...books.map(buildBookCard),
      ],
    );
  }

  Widget buildSavedBooksSection() {
    return Card(
      elevation: 1,
      child: ExpansionTile(
        initiallyExpanded: false,
        leading: const Icon(Icons.storage),
        title: const Text('Data Buku Tersimpan di Database'),
        subtitle: Text('${savedBooks.length} buku tersimpan'),
        trailing: isLoadingSavedBooks
            ? const SizedBox(
                width: 22,
                height: 22,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : IconButton(
                icon: const Icon(Icons.refresh),
                onPressed: loadSavedBooks,
              ),
        children: [
          if (savedBooks.isEmpty)
            const Padding(
              padding: EdgeInsets.all(16),
              child: Text('Belum ada data buku tersimpan.'),
            )
          else
            ...savedBooks.map(
              (book) => ListTile(
                leading: buildThumbnail(book.thumbnail),
                title: Text(
                  book.title,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                subtitle: Text(
                  'Penerbit: ${book.publisher ?? '-'}\n'
                  'Tanggal terbit: ${book.publishedDate ?? '-'}',
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget buildServerInfo() {
    return Card(
      elevation: 1,
      color: Colors.blue.shade50,
      child: const Padding(
        padding: EdgeInsets.all(12),
        child: Text(
          'Aplikasi ini mengambil data dari Google Books API, '
          'lalu menyimpan data buku ke database server melalui REST API. ',
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Google Books Importer'),
        actions: [
          IconButton(
            onPressed: loadSavedBooks,
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh data tersimpan',
          ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            buildServerInfo(),
            const SizedBox(height: 12),
            buildSearchForm(),
            const SizedBox(height: 12),
            buildActionButtons(),
            const SizedBox(height: 12),
            buildGoogleBooksResult(),
            const SizedBox(height: 12),
            buildSavedBooksSection(),
          ],
        ),
      ),
    );
  }
}
